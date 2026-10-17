"""Render every mockup page to PNG, so the designs can be reviewed on GitHub (which shows HTML as
source). Also fails on a console error or an in-page link that points at a missing file.

    .venv/bin/python docs/ui-docs/render.py            # every style
    .venv/bin/python docs/ui-docs/render.py style-1    # one style
    .venv/bin/python docs/ui-docs/render.py --phone    # also check 390px wide (not saved)
"""
import sys
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}


def main(argv: list[str]) -> int:
    phone = "--phone" in argv
    names = [a for a in argv if not a.startswith("--")]
    styles = [HERE / n for n in names] if names else sorted(HERE.glob("style-*"))
    problems = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for style in styles:
            out = style / "screenshots"
            out.mkdir(exist_ok=True)
            for page_file in sorted(style.glob("*.html")):
                for size, save in [(DESKTOP, True)] + ([(PHONE, False)] if phone else []):
                    page = browser.new_page(viewport=size)
                    errors = []
                    page.on("console", lambda m, e=errors: m.type == "error" and e.append(m.text))
                    page.on("pageerror", lambda exc, e=errors: e.append(str(exc)))
                    page.goto(page_file.as_uri())
                    page.wait_for_load_state("load")
                    for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))"):
                        target = urlparse(href)
                        if target.scheme or not target.path or href.startswith("#"):
                            continue
                        if not (page_file.parent / target.path).exists():
                            problems.append(f"{page_file.relative_to(HERE)}: broken link {href}")
                    if size is PHONE:
                        overflow = page.evaluate("document.documentElement.scrollWidth - innerWidth")
                        if overflow > 0:
                            problems.append(f"{page_file.relative_to(HERE)}: {overflow}px sideways scroll at phone width")
                    problems += [f"{page_file.relative_to(HERE)}: console: {e}" for e in errors]
                    if save:
                        page.screenshot(path=str(out / f"{page_file.stem}.png"), full_page=True)
                    page.close()
            print(f"rendered {style.name}")
        browser.close()
    for line in dict.fromkeys(problems):
        print("PROBLEM", line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
