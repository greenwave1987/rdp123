import os
import sys
import json
import time
import base64
import requests
import pyotp
from nacl import encoding, public
from datetime import datetime
from playwright.sync_api import sync_playwright, TimeoutError


TAILSCALE_LOGIN = "https://login.tailscale.com/login"
STATE_FILE = "tailscale_state.json"

GH_USER = os.getenv("GH_USER")
GH_PASS = os.getenv("GH_PASS")
GH_TOTP = os.getenv("GH_TOTP")

GH_TOKEN = os.getenv("GH_TOKEN")
GH_REPO = os.getenv("GH_REPO")
SECRET_NAME = os.getenv("SECRET_NAME")


def mask_key(key: str):
    if not key or len(key) < 10:
        return "***"
    return f"{key[:6]}***{key[-4:]}"

    
def log(msg):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}")
    sys.stdout.flush()


def totp_code():
    return pyotp.TOTP(GH_TOTP).now()


def wait_enabled(page, selector, timeout=20000):
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


def handle_2fa(page):
    log("检测 GitHub 2FA")
    selectors = ["#app_totp", "input[name='app_otp']", "#otp"]

    for s in selectors:
        try:
            page.wait_for_selector(s, timeout=8000)
            code = totp_code()
            log(f"输入 TOTP: {code}")
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


def delete_old_keys(page):
    log("获取并清理旧 AuthKeys...")

    # 还原你抓包获取的绝对路径请求
    result = page.evaluate("""
    async () => {
        try {
            const res = await fetch("https://login.tailscale.com/admin/api/public/tailnet/-/keys?includeInvalid=true", {
                headers: {
                    "accept": "application/json, text/plain, */*",
                    "cache-control": "no-cache",
                    "pragma": "no-cache"
                },
                referrer: "https://console.tailscale.com/",
                method: "GET",
                credentials: "include" // 关键：自动携带 tailcontrol 等 Cookie
            });

            const contentType = res.headers.get("content-type") || "";
            if (!contentType.includes("application/json")) {
                const text = await res.text();
                return { success: false, error: `非 JSON 响应 (HTTP ${res.status}): ${text.slice(0, 100)}` };
            }

            const data = await res.json();
            if (data.status !== "success") {
                return { success: false, data };
            }

            const keys = data.data?.keys || [];
            const activeKeys = keys.filter(k => !k.invalid && !k.revoked);
            const idsToDelete = activeKeys.map(k => k.id).filter(Boolean);

            if (idsToDelete.length === 0) {
                return { success: true, totalFound: keys.length, deletedCount: 0 };
            }

            const deletePromises = idsToDelete.map(id => 
                fetch(`https://login.tailscale.com/admin/api/public/tailnet/-/keys/${id}`, {
                    method: "DELETE",
                    headers: {
                        "accept": "application/json, text/plain, */*",
                        "cache-control": "no-cache"
                    },
                    referrer: "https://console.tailscale.com/",
                    credentials: "include"
                })
                .then(r => r.ok)
                .catch(() => false)
            );

            const results = await Promise.all(deletePromises);
            const deletedCount = results.filter(Boolean).length;

            return {
                success: true,
                totalFound: keys.length,
                deletedCount: deletedCount
            };
        } catch (err) {
            return { success: false, error: err.toString() };
        }
    }
    """)

    if result.get("success"):
        log(f"发现 {result['totalFound']} 个 Key，成功删除/撤销 {result['deletedCount']} 个活跃 Key")
    else:
        log(f"❌ 清理旧 Key 失败: {result}")


def create_authkey(page):
    log("创建新的 AuthKey")

    # 还原带 keyType 的完整 Payload 抓包数据
    result = page.evaluate("""
    async () => {
        try {
            const res = await fetch("https://login.tailscale.com/admin/api/public/tailnet/-/keys", {
                method: "POST",
                headers: {
                    "accept": "application/json, text/plain, */*",
                    "content-type": "application/json",
                    "cache-control": "no-cache"
                },
                referrer: "https://console.tailscale.com/",
                credentials: "include",
                body: JSON.stringify({
                    "keyType": "auth",
                    "description": "auto-generated",
                    "expirySeconds": 7776000,
                    "capabilities": {
                        "devices": {
                            "create": {
                                "ephemeral": false,
                                "reusable": false,
                                "preauthorized": false,
                                "tags": []
                            }
                        }
                    }
                })
            });

            const contentType = res.headers.get("content-type") || "";
            if (!contentType.includes("application/json")) {
                const text = await res.text();
                return { success: false, error: `请求失败 (HTTP ${res.status}): ${text.slice(0, 100)}` };
            }

            const data = await res.json();
            if (data.status === "success") {
                const keyVal = data.data?.key || data.data?.fullKey;
                return { success: true, key: keyVal };
            } else {
                return { success: false, data };
            }
        } catch (e) {
            return { success: false, error: e.toString() };
        }
    }
    """)

    if not result.get("success"):
        log(f"❌ 创建失败: {result}")
        raise Exception("Tailscale AuthKey 生成失败")

    key = result.get("key")
    if not key:
        raise KeyError("返回数据中未能识别到有效 Key 字符串")

    log(f"新 AuthKey: {mask_key(key)}")
    return key


def encrypt_secret(public_key, secret):
    pk = public.PublicKey(public_key.encode(), encoding.Base64Encoder())
    sealed_box = public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret.encode())
    return base64.b64encode(encrypted).decode()


def update_github_secret(secret_value):
    log("获取 GitHub 公钥")
    url = f"https://api.github.com/repos/{GH_REPO}/actions/secrets/public-key"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json"
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
        "key_id": key_id
    }

    put_res = requests.put(put_url, headers=headers, json=data)
    put_res.raise_for_status()
    log("GitHub Secret 更新完成")


def main():
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

            # 保持在控制台 Key 页面执行 fetch（保证 Referer 为 console.tailscale.com）
            page.goto('https://console.tailscale.com/admin/settings/keys', timeout=60000)
            page.wait_for_load_state("networkidle")

            delete_old_keys(page)
            authkey = create_authkey(page)

            if authkey:
                update_github_secret(authkey)

        except Exception as e:
            log(f"发生错误: {e}")

        finally:
            browser.close()
            log("浏览器关闭")


if __name__ == "__main__":
    main()
