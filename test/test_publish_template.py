"""Keep the publish template's secret-bearing dependencies immutable."""

import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublishTemplatePinTests(unittest.TestCase):
    def test_checkout_actions_use_full_commit_shas(self):
        template = (ROOT / "ci" / "publish.yml").read_text(encoding="utf-8")
        refs = re.findall(r"^\s*- uses: actions/checkout@([0-9a-f]+)\b", template, re.MULTILINE)
        self.assertEqual(len(refs), 2)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs), refs)

    def test_k18_checkout_uses_a_full_reviewed_commit_sha(self):
        template = (ROOT / "ci" / "publish.yml").read_text(encoding="utf-8")
        match = re.search(
            r"repository:\s*k18labs/k18\s+"
            r"# Update only through review to a full commit SHA from k18labs/k18\.\s+"
            r"ref:\s*([0-9a-f]+)",
            template,
        )
        self.assertIsNotNone(match)
        self.assertRegex(match.group(1), r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
