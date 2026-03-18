from playwright.sync_api import sync_playwright
import os

URL = "file:///C:/Users/hkmen/crypto-forensics-toolkit/index.html"
OUT = "C:/Users/hkmen/crypto-forensics-toolkit"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Desktop 1440px
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(URL)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT, "screenshot_desktop_full.png"), full_page=True)
        page.screenshot(path=os.path.join(OUT, "screenshot_desktop_hero.png"))
        print("Desktop screenshots done")

        # Mobile 375px
        page2 = browser.new_page(viewport={"width": 375, "height": 812})
        page2.goto(URL)
        page2.wait_for_load_state("networkidle")
        page2.wait_for_timeout(1000)
        page2.screenshot(path=os.path.join(OUT, "screenshot_mobile_full.png"), full_page=True)
        page2.screenshot(path=os.path.join(OUT, "screenshot_mobile_hero.png"))

        # Open hamburger menu on mobile
        hamburger = page2.locator(".hamburger")
        if hamburger.is_visible():
            hamburger.click()
            page2.wait_for_timeout(500)
            page2.screenshot(path=os.path.join(OUT, "screenshot_mobile_menu.png"))
            print("Mobile menu screenshot done")

        print("Mobile screenshots done")
        browser.close()
        print("All done")


if __name__ == "__main__":
    main()
