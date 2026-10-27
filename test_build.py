import pathlib
import re
import unittest

import build

HERE = pathlib.Path(__file__).parent


class BuildTest(unittest.TestCase):
    def test_each_page_has_every_marker_filled(self):
        for name, html in build.build_all().items():
            with self.subTest(name):
                self.assertNotRegex(html, r"/\*[A-Z]+\*/|<!--[A-Z]+-->")

    def test_the_logo_is_inline_without_the_illustrator_prolog(self):
        for name, html in build.build_all().items():
            with self.subTest(name):
                self.assertIn("<svg", html)
                self.assertNotIn("<?xml", html)

    def test_committed_pages_match_the_build(self):
        for name, html in build.build_all().items():
            with self.subTest(name):
                self.assertEqual((HERE / name).read_text(encoding="utf-8"), html,
                                 f"{name} is stale: run python3 build.py")

    def test_nothing_in_src_points_outside_the_repo(self):
        for path in (HERE / "src").rglob("*"):
            if path.is_file():
                with self.subTest(path.name):
                    self.assertIsNone(re.search(r"/Users/|GL-\d", path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
