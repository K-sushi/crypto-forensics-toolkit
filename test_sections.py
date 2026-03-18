from playwright.sync_api import sync_playwright
URL = "file:///C:/Users/hkmen/crypto-forensics-toolkit/index.html"
OUT = "C:/Users/hkmen/crypto-forensics-toolkit"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(URL)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(800)

        # Pain section (white contrast)
        pain = page.locator("#pain")
        pain.screenshot(path=f"{OUT}/ss_pain.png")

        # Results section (dashboard)
        results = page.locator("#results")
        results.screenshot(path=f"{OUT}/ss_results.png")

        # Mobile menu
        page2 = browser.new_page(viewport={"width": 375, "height": 812})
        page2.goto(URL)
        page2.wait_for_load_state("networkidle")
        page2.wait_for_timeout(500)
        page2.locator(".hamburger").click()
        page2.wait_for_timeout(400)
        page2.screenshot(path=f"{OUT}/ss_mobile_menu.png")

        browser.close()
        print("Done")


if __name__ == "__main__":
    main()
