#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tailscale AuthKey + API Key 自动轮换脚本
流程：
1. 使用 Playwright 登录 Tailscale（GitHub OAuth + 2FA）
2. 提取 Cookies 构建 requests.Session
3. 删除所有旧的有效 AuthKey 和 API Key
4. 创建新的 AuthKey
5. 更新 GitHub Actions Secret
6. 创建新的 API Key（keyType=api）
7. 更新 GitHub Actions Secret
依赖环境变量：
    GH_USER
    GH_PASS
    GH_TOTP
    GH_TOKEN
    GH_REPO
    SECRET_NAME
可选：
    API_SECRET_NAME
依赖：
    pip install playwright requests pyotp pynacl
    playwright install chromium
"""
import os
import sys
import json
import time
import base64
from datetime import datetime
import requests
import pyotp
from nacl import encoding, public
from playwright.sync_api import sync_playwright, TimeoutError
TAILSCALE_LOGIN = "https://login.tailscale.com/login"
STATE_FILE = "tailscale_state.json"
GH_USER = os.getenv("GH_USER")
GH_PASS = os.getenv("GH_PASS")
GH_TOTP = os.getenv("GH_TOTP")
GH_TOKEN = os.getenv("GH_TOKEN")
GH_REPO = os.getenv("GH_REPO")
SECRET_NAME = os.getenv("SECRET_NAME")
API_SECRET_NAME = os.getenv("API_SECRET_NAME", "TAILSCALE_API_KEY")
KEY_EXPIRY_SECONDS = 7776000
REQUIRED_ENV_VARS = [
    "GH_USER",
    "GH_PASS",
    "GH_TOTP",
    "GH_TOKEN",
    "GH_REPO",
    "SECRET_NAME",
]
def log(msg: str):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}")
    sys.stdout.flush()
def check_env():
    missing = [name for name in REQUIRED_ENV_VARS if not os.getenv(name)]
    if missing:
        log(f"❌ 缺少必需的环境变量: {', '.join(missing)}")
        sys.exit(1)
    log("✅ 环境变量检查通过")
    log(f"GitHub 仓库: {GH_REPO}")
    log(f"AuthKey Secret: {SECRET_NAME}")
    log(f"API Key Secret: {API_SECRET_NAME}")
def mask_key(key: str) -> str:
    if not key or len(key) < 10:
        return "***"
    return f"{key[:6]}***{key[-4:]}"
def totp_code() -> str:
    return pyotp.TOTP(GH_TOTP).now()
def wait_enabled(page, selector: str, timeout: int = 20000):
    page.wait_for_function(
        f"""() => {{
        const el = document.querySelector("{selector}");
        return el && !el.disabled;
    }}""",
        timeout=timeout,
    )
def handle_github_login(page):
    log("点击 GitHub 登录")
    page.locator("button:has-text('GitHub')").click()
    page.wait_for_url("**github.com/login**", timeout=30000)
    log("填写 GitHub 用户名")
    page.fill("#login_field", GH_USER)
    log("填写 GitHub 密码")
    page.fill("#password", GH_PASS)
    page.locator("input[name='commit']").click()
def handle_2fa(page) -> bool:
    log("检测 GitHub 2FA")
    selectors = ["#app_totp", "input[name='app_otp']", "#otp"]
    for selector in selectors:
        try:
            page.wait_for_selector(selector, timeout=8000)
            code = totp_code()
            log("输入 TOTP 验证码")
            page.fill(selector, code)
            page.keyboard.press("Enter")
            return True
        except TimeoutError:
            continue
    log("未检测到 2FA")
    return False
def handle_oauth(page):
    log("检测 OAuth 页面")
    try:
        btn = page.locator("button.js-oauth-authorize-btn")
        btn.wait_for(state="visible", timeout=20000)
        wait_enabled(page, "button.js-oauth-authorize-btn")
        log("点击 Authorize tailscale")
        btn.click()
    except Exception:
        log("未出现 OAuth 页面")
def save_state(context):
    log("保存登录状态")
    state = context.storage_state()
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
def load_state(browser):
    if os.path.exists(STATE_FILE):
        log("加载已保存登录状态")
        return browser.new_context(storage_state=STATE_FILE)
    log("未找到登录状态，创建新的浏览器上下文")
    return browser.new_context()
def build_requests_session(context) -> requests.Session:
    log("构建 requests Session")
    session = requests.Session()
    cookies = context.cookies()
    log(f"提取 Cookies 数量: {len(cookies)}")
    for cookie in cookies:
        try:
            session.cookies.set(
                cookie["name"],
                cookie["value"],
                domain=cookie["domain"],
                path=cookie["path"],
            )
        except Exception as e:
            log(f"⚠️ Cookie 写入失败 {cookie.get('name')}: {e}")
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Origin": "https://console.tailscale.com",
        "Referer": "https://console.tailscale.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    return session
def get_keys_requests(session: requests.Session):
    url = "https://login.tailscale.com/admin/api/public/tailnet/-/keys?includeInvalid=true"
    log("获取 Tailscale Key 列表")
    try:
        res = session.get(url, timeout=30)
        if res.status_code != 200:
            log(f"❌ 获取 Key 列表失败 (HTTP {res.status_code})")
            log(f"响应: {res.text[:500]}")
            return []
        data = res.json()
        if data.get("status") != "success":
            log(f"❌ 获取 Key 列表返回异常: {data}")
            return []
        keys = data.get("data", {}).get("keys", [])
        log(f"📋 Tailscale Key 总数: {len(keys)}")
        return keys
    except Exception as e:
        log(f"❌ 获取 Key 列表异常: {e}")
        return []
def delete_old_keys(session: requests.Session):
    log("开始清理所有旧 Key")
    keys = get_keys_requests(session)
    if not keys:
        log("ℹ️ 没有获取到 Key")
        return
    active_keys = [
        key for key in keys
        if not key.get("invalid") and not key.get("revoked") and key.get("id")
    ]
    log(f"发现 {len(active_keys)} 个活跃 Key")
    if not active_keys:
        log("ℹ️ 没有需要删除的旧 Key")
        return
    deleted_count = 0
    failed_count = 0
    for key in active_keys:
        key_id = key.get("id")
        key_type = key.get("keyType") or key.get("type") or "unknown"
        description = key.get("description", "")
        del_url = f"https://login.tailscale.com/admin/api/public/tailnet/-/keys/{key_id}"
        try:
            log(f"🗑️ 删除 Key | ID={key_id} | Type={key_type} | Description={description}")
            del_res = session.delete(del_url, timeout=30)
            if del_res.status_code in (200, 204):
                deleted_count += 1
                log(f"✅ 删除成功: {key_id}")
            else:
                failed_count += 1
                log(f"❌ 删除失败: {key_id} (HTTP {del_res.status_code})")
                log(del_res.text[:300])
        except Exception as e:
            failed_count += 1
            log(f"❌ 删除 Key 异常 {key_id}: {e}")
    log(f"🧹 Key 清理完成: 成功 {deleted_count}，失败 {failed_count}")
def create_authkey_requests(session: requests.Session) -> str:
    log("创建新的 AuthKey")
    url = "https://login.tailscale.com/admin/api/public/tailnet/-/keys"
    payload = {
        "keyType": "auth",
        "description": "auto-generated",
        "expirySeconds": KEY_EXPIRY_SECONDS,
        "capabilities": {
            "devices": {
                "create": {
                    "ephemeral": False,
                    "reusable": True,
                    "preauthorized": False,
                    "tags": [],
                }
            }
        },
    }
    try:
        res = session.post(url, json=payload, timeout=30)
    except Exception as e:
        log(f"❌ 创建 AuthKey 请求异常: {e}")
        raise
    if res.status_code != 200:
        log(f"❌ 创建 AuthKey 失败 (HTTP {res.status_code})")
        log(f"响应: {res.text[:500]}")
        raise RuntimeError("Tailscale AuthKey 创建失败")
    try:
        data = res.json()
    except Exception:
        log(f"❌ API 返回非 JSON: {res.text[:500]}")
        raise
    if data.get("status") != "success":
        log(f"❌ AuthKey API 返回错误: {data}")
        raise RuntimeError("Tailscale AuthKey 生成失败")
    key_val = data.get("data", {}).get("key") or data.get("data", {}).get("fullKey")
    if not key_val:
        raise KeyError(f"未找到 AuthKey 字段: {data}")
    log(f"✅ 新 AuthKey: {mask_key(key_val)}")
    return key_val
def create_apikey_requests(session: requests.Session) -> str:
    log("创建新的 Tailscale API Key")
    url = "https://login.tailscale.com/admin/api/public/tailnet/-/keys"
    payload = {
        "keyType": "api",
        "description": "auto-generated-api",
        "expirySeconds": KEY_EXPIRY_SECONDS,
    }
    log(f"API Key 参数: keyType=api, expirySeconds={KEY_EXPIRY_SECONDS}")
    try:
        res = session.post(url, json=payload, timeout=30)
    except Exception as e:
        log(f"❌ 创建 API Key 请求异常: {e}")
        raise
    if res.status_code != 200:
        log(f"❌ 创建 API Key 失败 (HTTP {res.status_code})")
        log(f"响应: {res.text[:500]}")
        raise RuntimeError("Tailscale API Key 创建失败")
    try:
        data = res.json()
    except Exception:
        log(f"❌ API 返回非 JSON: {res.text[:500]}")
        raise
    if data.get("status") != "success":
        log(f"❌ API Key 返回错误: {data}")
        raise RuntimeError("Tailscale API Key 生成失败")
    key_val = data.get("data", {}).get("key") or data.get("data", {}).get("fullKey")
    if not key_val:
        raise KeyError(f"未找到 API Key 字段: {data}")
    log(f"✅ 新 API Key: {mask_key(key_val)}")
    return key_val
def encrypt_secret(public_key: str, secret: str) -> str:
    pk = public.PublicKey(public_key.encode(), encoding.Base64Encoder())
    sealed_box = public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret.encode())
    return base64.b64encode(encrypted).decode()
def update_github_secret(secret_name: str, secret_value: str):
    log(f"准备更新 GitHub Secret: {secret_name}")
    url = f"https://api.github.com/repos/{GH_REPO}/actions/secrets/public-key"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
    except Exception as e:
        log(f"❌ 获取 GitHub 公钥失败: {e}")
        if "r" in locals():
            log(r.text[:500])
        raise
    public_key = r.json()["key"]
    key_id = r.json()["key_id"]
    encrypted = encrypt_secret(public_key, secret_value)
    put_url = f"https://api.github.com/repos/{GH_REPO}/actions/secrets/{secret_name}"
    data = {
        "encrypted_value": encrypted,
        "key_id": key_id,
    }
    log(f"更新 GitHub Secret: {secret_name}")
    try:
        put_res = requests.put(
            put_url,
            headers=headers,
            json=data,
            timeout=30
        )
        put_res.raise_for_status()
    except Exception as e:
        log(f"❌ GitHub Secret 更新失败: {e}")
        if "put_res" in locals():
            log(put_res.text[:500])
        raise
    log(f"✅ GitHub Secret 更新完成: {secret_name}")
def main():
    check_env()
    log("=" * 60)
    log("🚀 Tailscale AuthKey + API Key 自动轮换开始")
    log("=" * 60)
    log(f"Key 有效期: {KEY_EXPIRY_SECONDS} 秒 (90 天)")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        context = load_state(browser)
        page = context.new_page()
        try:
            log("打开 Tailscale 登录页面")
            page.goto(TAILSCALE_LOGIN, timeout=60000)
            log(f"当前 URL: {page.url}")
            if "login" in page.url:
                handle_github_login(page)
                time.sleep(2)
                handle_2fa(page)
                handle_oauth(page)
            page.wait_for_url("**tailscale.com/**", timeout=120000)
            log("✅ Tailscale 登录成功")
            save_state(context)
            log("打开 Tailscale Key 管理页面")
            page.goto(
                "https://console.tailscale.com/admin/settings/keys",
                timeout=60000
            )
            try:
                page.wait_for_load_state("networkidle", timeout=30000)
            except TimeoutError:
                log("⚠️ networkidle 等待超时，继续执行")
            http_session = build_requests_session(context)
            delete_old_keys(http_session)
            authkey = create_authkey_requests(http_session)
            update_github_secret(SECRET_NAME, authkey)
            log(f"✅ AuthKey 已写入 GitHub Secret: {SECRET_NAME}")
            apikey = create_apikey_requests(http_session)
            update_github_secret(API_SECRET_NAME, apikey)
            log(f"✅ API Key 已写入 GitHub Secret: {API_SECRET_NAME}")
            log("=" * 60)
            log("🎉 Tailscale Key 自动轮换完成")
            log("=" * 60)
        except Exception as e:
            log("=" * 60)
            log(f"❌ 发生错误: {e}")
            log("=" * 60)
            raise
        finally:
            browser.close()
            log("浏览器关闭")
if __name__ == "__main__":
    main()
