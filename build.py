#!/usr/bin/env python3
"""Build the three Wi-Fi report pages from src/, each one self-contained HTML file.

The parsing and the reports live in src/wdutil.js, src/netsh.js and src/lswifi.js. This script
only inlines the style sheets, scripts, logo and example into each page template.

Usage:
    python3 build.py
"""
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "src"


def read(name):
    return (SRC / name).read_text(encoding="utf-8")


def script_string(text):
    return json.dumps(text).replace("</", "<\\/")


def inline_logo():
    # Inline SVG must not carry the Illustrator XML prolog or comment.
    return re.sub(r"<\?xml.*?\?>|<!--.*?-->", "", read("wlanpros-logo-white.svg"), flags=re.S).strip()


def fill(template, style, script, example, netsh=""):
    page = read(template)
    replacements = {
        "/*STYLE*/": style,
        "<!--LOGO-->": inline_logo(),
        "/*SCRIPT*/": script,
        "/*NETSH*/": netsh,
        '/*EXAMPLE*/""': script_string(read(example)),
        "/*INPUT*/null": "null",
        "/*REDACT*/true": "true",
    }
    for marker, value in replacements.items():
        page = page.replace(marker, value)
    return page


def build_all():
    return {
        "mac-wifi-report.html": fill("mac-page.html", read("style.css"), read("wdutil.js"),
                                     "examples/mac-wdutil.txt"),
        "windows-wifi-report.html": fill("windows-page.html", read("style.css"), read("wdutil.js"),
                                         "examples/windows-netsh.txt", netsh=read("netsh.js")),
        "nearby-wifi-report.html": fill("nearby-page.html", read("style.css") + read("nearby.css"),
                                        read("lswifi.js"), "examples/nearby-lswifi.json"),
    }


def main():
    for name, html in build_all().items():
        (HERE / name).write_text(html, encoding="utf-8")
        print(name)


if __name__ == "__main__":
    main()
