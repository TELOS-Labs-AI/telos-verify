"""The README's statements about the test suite and the vectors stay true (V1, V2, V5)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


class ReadmeTestCountMatchesTheSuite(unittest.TestCase):
    def test_every_stated_test_count_equals_the_discovered_count(self):
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        discovered = suite.countTestCases()
        self.assertGreater(discovered, 0)
        stated = {int(n) for n in re.findall(r"^(\d+) tests\.", README, re.MULTILINE)}
        stated |= {int(n) for n in re.findall(r"`Ran (\d+) tests`", README)}
        self.assertTrue(stated, "README states no test count")
        self.assertEqual(stated, {discovered})


class ReadmeDefinesWhatItCites(unittest.TestCase):
    def test_the_cited_standard_and_its_terms_are_explained(self):
        self.assertIn("TELOS Receipt Standard v0.1", README)  # still cited
        terms = README.split("## Terms", 1)
        self.assertEqual(len(terms), 2, "README has no Terms section")
        section = terms[1].split("\n## ", 1)[0]
        for term in ("TELOS Receipt Standard v0.1", "not yet published", "S3", "TRS",
                     "Lineage Chain", "trs-cert/0.1", "trs-lineage-projection/0.1"):
            self.assertIn(term, section)


class ReadmeVectorsAreNotPresentedAsClaims(unittest.TestCase):
    def test_disclaimer_sits_beside_the_valid_vector_walkthrough(self):
        walkthrough = README.split("### 1. A chain that verifies", 1)[1].split("```", 1)[0]
        self.assertIn("test fixtures", walkthrough)
        self.assertIn("not benchmark claims", walkthrough)
        self.assertNotIn("someone restating a result", README)


if __name__ == "__main__":
    unittest.main()
