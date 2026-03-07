import os
import sys
import json
import time
import pyotp
from datetime import datetime
from playwright.sync_api import sync_playwright, TimeoutError

TAILSCALE_LOGIN = "https://login.tailscale.com/login"
STORAGE_FILE = "tailscale_state.json"

GH_USER = os.getenv("GH_USER")
GH_PASS = os.getenv("GH_PASS")
GH_TOTP = os.getenv("GH_TOTP")


def log(msg):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}")
    sys.stdout.flush()


def get_totp():
    return pyotp.TOTP(GH_TOTP).now()


def login_with_github(page):

    log("点击 GitHub 登录")
    page.click("button:has-text('GitHub')")

    log("等待跳转 GitHub 登录页")
    page.wait_for_url("**github.com/login**", timeout=30000)

    log("填写 GitHub 用户名")
    page.fill("#login_field", GH_USER)

    log("填写 GitHub 密码")
    page.fill("#password", GH_PASS)

    log("提交登录")
    page.click("input[name='commit']")


def handle_2fa(page):

    log("检测 GitHub 2FA 页面")

    selectors = [
        "#app_totp",
        "input[name='app_otp']",
        "#otp"
    ]

    for sel in selectors:
        try:

            page.wait_for_selector(sel, timeout=5000)

            code = get_totp()

            log(f"生成 TOTP: {code}")

            page.fill(sel, code)

            log("提交验证码")
            page.keyboard.press("Enter")

            return True

        except TimeoutError:
            continue

    log("未检测到 2FA")
    return False


def save_state(context):

    state = context.storage_state()

    with open(STORAGE_FILE, "w") as f:
        json.dump(state, f)

    log("登录状态已保存")


def load_state(context):

    if os.path.exists(STORAGE_FILE):
        log("加载已有登录状态")
        context = context.browser.new_context(storage_state=STORAGE_FILE)
        return context

    return context


def main():

    log("启动 Playwright")

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"]
        )

        context = browser.new_context()

        page = context.new_page()

        try:

            log("打开 Tailscale 登录页")

            page.goto(TAILSCALE_LOGIN, timeout=60000)

            if "login" in page.url:

                login_with_github(page)

                time.sleep(3)

                handle_2fa(page)

            log("等待跳转回 Tailscale")

            page.wait_for_url("**tailscale.com/**", timeout=60000)

            log(f"登录成功: {page.url}")

            save_state(context)

        except Exception as e:

            log(f"发生错误: {e}")

        finally:

            browser.close()

            log("浏览器关闭")


if __name__ == "__main__":
    main()
