import os
import sys
import json
import time
import pyotp
from datetime import datetime
from playwright.sync_api import sync_playwright, TimeoutError

TAILSCALE_LOGIN = "https://login.tailscale.com/login"
STATE_FILE = "tailscale_state.json"

GH_USER = os.getenv("GH_USER")
GH_PASS = os.getenv("GH_PASS")
GH_TOTP = os.getenv("GH_TOTP")


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

    log("等待 GitHub 登录页")

    page.wait_for_url("**github.com/login**", timeout=30000)

    log("填写用户名")

    page.fill("#login_field", GH_USER)

    log("填写密码")

    page.fill("#password", GH_PASS)

    log("提交登录")

    page.locator("input[name='commit']").click()


def handle_2fa(page):

    log("检测 GitHub 2FA")

    selectors = [
        "#app_totp",
        "input[name='app_otp']",
        "#otp"
    ]

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

    log("检测 OAuth 授权页面")

    try:

        btn = page.locator("button.js-oauth-authorize-btn")

        btn.wait_for(state="visible", timeout=20000)

        log("等待 Authorize 按钮可点击")

        wait_enabled(page, "button.js-oauth-authorize-btn")

        btn.scroll_into_view_if_needed()

        log("点击 Authorize tailscale")

        btn.click()

        return True

    except Exception:

        log("未出现 OAuth 授权页面")

        return False


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

            log("打开 Tailscale 登录页")

            page.goto(TAILSCALE_LOGIN, timeout=60000)

            log(f"当前URL: {page.url}")

            if "login" in page.url:

                handle_github_login(page)

                time.sleep(2)

                handle_2fa(page)

                handle_oauth(page)

            log("等待跳转回 Tailscale")

            page.wait_for_url("**tailscale.com/**", timeout=120000)

            log(f"登录成功 -> {page.url}")

            save_state(context)

        except Exception as e:

            log(f"发生错误: {e}")

        finally:

            browser.close()

            log("浏览器关闭")


if __name__ == "__main__":
    main()
