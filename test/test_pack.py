"""Tests for packed site response selection."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import pack  # noqa: E402


class BrotliSelectionTests(unittest.TestCase):
    def pack_with_sizes(self, gzip_size, brotli_size):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site, out = root / "site", root / "out"
            site.mkdir()
            body = b"x" * 3000
            (site / "large.txt").write_bytes(body)
            out.mkdir()
            env = {"COMPRESS": "1", "CACHE": "600", "HSTS": "", "HEADERS": ""}
            with patch.dict(os.environ, env, clear=False), \
                    patch.object(pack.gzip, "compress", return_value=b"g" * gzip_size), \
                    patch.object(pack, "brotli_encoder", return_value=lambda _: b"b" * brotli_size):
                pack.main(str(site), str(out))
            metadata = json.loads((out / "site.json").read_text())
            return metadata["paths"]["/large.txt"].get("forms", {})

    def test_brotli_can_qualify_when_gzip_misses_ten_percent(self):
        forms = self.pack_with_sizes(gzip_size=2820, brotli_size=2300)
        self.assertIn("br", forms)
        self.assertNotIn("gzip", forms)

    def test_brotli_is_omitted_without_an_additional_wire_record(self):
        forms = self.pack_with_sizes(gzip_size=2500, brotli_size=2499)
        self.assertIn("gzip", forms)
        self.assertNotIn("br", forms)


if __name__ == "__main__":
    unittest.main()
