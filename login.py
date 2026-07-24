#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tailscale AuthKey 自动轮换脚本

流程：
1. 使用 Playwright 登录 Tailscale（通过 GitHub OAuth，支持 2FA）
2. 登录成功后提取 Cookies，构建 requests.Session 调用 Tailscale 内部 API
3. 删除/撤销旧的活跃 AuthKey
4. 创建新的 AuthKey
5. 将新 Key 加密后写入 GitHub Actions Secret

依赖环境变量：
    GH_USER      GitHub 用户名
    GH_PASS      GitHub 密码
    GH_TOTP      GitHub 2FA TOTP Secret
    GH_TOKEN     具备 repo secrets 写权限的 GitHub Token
    GH_REPO      目标仓库，格式 "owner/repo"
    SECRET_NAME  要写入的 Secret 名称

依赖库：
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


# ================= 配置 =================

TAILSCALE_LOGIN = "https://login.tailscale.com/login"
STATE_FILE = "tailscale_state.json"

GH_USER = os.getenv("GH_USER")
GH_PASS = os.getenv("GH_PASS")
GH_TOTP = os.getenv("GH_TOTP")

GH_TOKEN = os.getenv("GH_TOKEN")
GH_REPO = os.getenv("GH_REPO")
SECRET_NAME = os.getenv("SECRET_NAME")

REQUIRED_ENV_VARS = [
    "GH_USER", "GH_PASS", "GH_TOTP", "GH_TOKEN", "GH_REPO", "SECRET_NAME",
]


# ================= 工具函数 =================

def check_env():
    """启动前检查必需的环境变量是否齐全"""
    missing = [name for name in REQUIRED_ENV_VARS if not os.getenv(name)]
    if missing:
        log(f"❌ 缺少必需的环境变量: {', '.join(missing)}")
        sys.exit(1)


def mask_key(key: str) -> str:
    if not key or len(key) < 10:
        return "***"
    return f"{key[:6]}***{key[-4:]}"


def log(msg: str):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}")
    sys.stdout.flush()


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


# ================= 登录流程 =================

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

    for s in selectors:
        try:
            page.wait_for_selector(s, timeout=8000)
            code = totp_code()
            log("输入 TOTP 验证码")
            page.fill(s, code)
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
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def load_state(browser):
    if os.path.exists(STATE_FILE):
        log("加载已保存登录状态")
        return browser.new_context(storage_state=STATE_FILE)
    return browser.new_context()


# ================= requests Session 构造与 API 操作 =================

def build_requests_session(context) -> requests.Session:
    """提取 Playwright 的 Cookies 并构建模拟 Chromium 请求头的 requests Session"""
    session = requests.Session()

    for cookie in context.cookies():
        session.cookies.set(
            cookie["name"],
            cookie["value"],
            domain=cookie["domain"],
            path=cookie["path"],
        )

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
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


def delete_old_keys_requests(session: requests.Session):
    """获取并清理旧 AuthKeys"""
    log("获取并清理旧 AuthKeys...")
    url = "https://login.tailscale.com/admin/api/public/tailnet/-/keys?includeInvalid=true"

    try:
        res = session.get(url)
        if res.status_code != 200:
            log(f"❌ 获取列表失败 (HTTP {res.status_code}): {res.text[:100]}")
            return

        data = res.json()
        if data.get("status") != "success":
            log(f"❌ 获取列表返回异常: {data}")
            return

        keys = data.get("data", {}).get("keys", [])

        active_keys = [k for k in keys if not k.get("invalid") and not k.get("revoked")]
        ids_to_delete = [k.get("id") for k in active_keys if k.get("id")]

        if not ids_to_delete:
            log(f"发现 {len(keys)} 个 Key，成功删除/撤销 0 个活跃 Key")
            return

        deleted_count = 0
        for key_id in ids_to_delete:
            del_url = f"https://login.tailscale.com/admin/api/public/tailnet/-/keys/{key_id}"
            del_res = session.delete(del_url)
            if del_res.status_code == 200:
                deleted_count += 1

        log(f"发现 {len(keys)} 个 Key，成功删除/撤销 {deleted_count} 个活跃 Key")

    except Exception as e:
        log(f"❌ 清理旧 Key 异常: {e}")


def create_authkey_requests(session: requests.Session) -> str:
    """创建新 AuthKey"""
    log("创建新的 AuthKey...")
    url = "https://login.tailscale.com/admin/api/public/tailnet/-/keys"

    payload = {
        "keyType": "auth",
        "description": "auto-generated",
        "expirySeconds": 7776000,
        "capabilities": {
            "devices": {
                "create": {
                    "ephemeral": False,
                    "reusable": False,
                    "preauthorized": False,
                    "tags": [],
                }
            }
        },
    }

    res = session.post(url, json=payload)
    if res.status_code != 200:
        log(f"❌ 创建失败 (HTTP {res.status_code}): {res.text[:150]}")
        raise RuntimeError("Tailscale API 请求未成功")

    data = res.json()
    if data.get("status") != "success":
        log(f"❌ API 返回错误: {data}")
        raise RuntimeError("Tailscale AuthKey 生成失败")

    key_val = data.get("data", {}).get("key") or data.get("data", {}).get("fullKey")
    if not key_val:
        raise KeyError("未查找到有效的 Key 字段")

    log(f"新 AuthKey: {mask_key(key_val)}")
    return key_val


# ================= GitHub Secret 更新部分 =================

def encrypt_secret(public_key: str, secret: str) -> str:
    pk = public.PublicKey(public_key.encode(), encoding.Base64Encoder())
    sealed_box = public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret.encode())
    return base64.b64encode(encrypted).decode()


def update_github_secret(secret_value: str):
    log("获取 GitHub 公钥")
    url = f"https://api.github.com/repos/{GH_REPO}/actions/secrets/public-key"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

    r = requests.get(url, headers=headers)
    r.raise_for_status()

    key = r.json()["key"]
    key_id = r.json()["key_id"]

    encrypted = encrypt_secret(key, secret_value)

    log("更新 GitHub Secret")
    put_url = f"https://api.github.com/repos/{GH_REPO}/actions/secrets/{SECRET_NAME}"
    data = {
        "encrypted_value": encrypted,
        "key_id": key_id,
    }

    put_res = requests.put(put_url, headers=headers, json=data)
    put_res.raise_for_status()
    log("GitHub Secret 更新完成")


# ================= 主程序 =================

def main():
    check_env()
    log("启动浏览器")

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
            page.goto(TAILSCALE_LOGIN, timeout=60000)
            log(f"当前URL: {page.url}")

            if "login" in page.url:
                handle_github_login(page)
                time.sleep(2)
                handle_2fa(page)
                handle_oauth(page)

            page.wait_for_url("**tailscale.com/**", timeout=120000)
            log("登录成功")

            save_state(context)

            # 跳转至控制台 Key 页面加载完整 Cookie 作用域
            page.goto("https://console.tailscale.com/admin/settings/keys", timeout=60000)
            page.wait_for_load_state("networkidle")

            # 构建带完整 Cookies 和完整安全 Header 的 requests Session
            http_session = build_requests_session(context)

            delete_old_keys_requests(http_session)
            authkey = create_authkey_requests(http_session)

            if authkey:
                update_github_secret(authkey)

        except Exception as e:
            log(f"发生错误: {e}")

        finally:
            browser.close()
            log("浏览器关闭")


if __name__ == "__main__":
    main()
