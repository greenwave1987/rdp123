import os
import pyotp
from playwright.sync_api import sync_playwright

TAILSCALE_LOGIN = "https://login.tailscale.com/login"

GITHUB_USER = os.getenv("GH_USER")
GITHUB_PASS = os.getenv("GH_PASS")
GITHUB_TOTP_SECRET = os.getenv("GH_TOTP")


def get_totp():
    totp = pyotp.TOTP(GITHUB_TOTP_SECRET)
    return totp.now()


with sync_playwright() as p:

    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    print("打开 Tailscale 登录页")
    page.goto(TAILSCALE_LOGIN)

    print("点击 GitHub 登录")
    page.click("button:has-text('GitHub')")

    page.wait_for_url("**github.com/login**")

    print("输入 GitHub 账号密码")

    page.fill("#login_field", GITHUB_USER)
    page.fill("#password", GITHUB_PASS)

    page.click("input[name='commit']")

    # 等待 2FA 页面
    try:
        page.wait_for_selector("input[name='otp']", timeout=10000)

        code = get_totp()

        print("输入 TOTP:", code)

        page.fill("input[name='otp']", code)

        page.click("button:has-text('Verify')")

    except:
        print("未检测到 2FA")

    print("等待返回 Tailscale")

    page.wait_for_url("**tailscale.com/**", timeout=60000)

    print("登录成功:", page.url)

    browser.close()
