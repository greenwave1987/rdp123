import os
import sys
import pyotp
import time
from datetime import datetime
from playwright.sync_api import sync_playwright, TimeoutError

TAILSCALE_LOGIN = "https://login.tailscale.com/login"

GITHUB_USER = os.getenv("GH_USER")
GITHUB_PASS = os.getenv("GH_PASS")
GITHUB_TOTP_SECRET = os.getenv("GH_TOTP")


def log(msg):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}")
    sys.stdout.flush()


def get_totp():
    totp = pyotp.TOTP(GITHUB_TOTP_SECRET)
    return totp.now()


def main():

    log("启动浏览器")

    with sync_playwright() as p:

        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:

            log("打开 Tailscale 登录页")
            page.goto(TAILSCALE_LOGIN, timeout=60000)

            log("点击 GitHub 登录按钮")
            page.click("button:has-text('GitHub')")

            log("等待跳转 GitHub 登录页")
            page.wait_for_url("**github.com/login**", timeout=30000)

            log("填写 GitHub 用户名")
            page.fill("#login_field", GITHUB_USER)

            log("填写 GitHub 密码")
            page.fill("#password", GITHUB_PASS)

            log("提交登录")
            page.click("input[name='commit']")

            log("检测是否需要 2FA")

            try:
                page.wait_for_selector("input[name='otp']", timeout=10000)

                code = get_totp()

                log(f"生成 TOTP: {code}")

                page.fill("input[name='otp']", code)

                log("提交 2FA 验证")
                page.click("button:has-text('Verify')")

            except TimeoutError:
                log("未检测到 2FA")

            log("等待跳转回 Tailscale")

            page.wait_for_url("**tailscale.com/**", timeout=60000)

            log(f"登录成功 -> {page.url}")

        except Exception as e:

            log(f"发生错误: {e}")

        finally:

            log("关闭浏览器")
            browser.close()


if __name__ == "__main__":
    main()
