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


class SiteSymlinkTests(unittest.TestCase):
    def pack(self, site, out):
        env = {"COMPRESS": "0", "CACHE": "600", "HSTS": "", "HEADERS": ""}
        with patch.dict(os.environ, env, clear=False):
            pack.main(str(site), str(out))

    def test_rejects_file_symlink_before_reading_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site, out = root / "site", root / "out"
            site.mkdir()
            out.mkdir()
            target = root / "secret.txt"
            target.write_text("synthetic secret", encoding="utf-8")
            (site / "public.txt").symlink_to(target)

            with self.assertRaisesRegex(SystemExit, "public.txt must not be a symlink"):
                self.pack(site, out)
            self.assertFalse((out / "site.bin").exists())

    def test_rejects_directory_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site, outside, out = root / "site", root / "outside", root / "out"
            site.mkdir()
            outside.mkdir()
            out.mkdir()
            (outside / "secret.txt").write_text("synthetic secret", encoding="utf-8")
            (site / "linked").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(SystemExit, "linked must not be a symlink"):
                self.pack(site, out)
            self.assertFalse((out / "site.bin").exists())

    def test_rejects_site_root_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside, out = root / "outside", root / "out"
            outside.mkdir()
            out.mkdir()
            (outside / "secret.txt").write_text("synthetic secret", encoding="utf-8")
            site = root / "site"
            site.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(SystemExit, "site directory must not be a symlink"):
                self.pack(f"{site}{os.sep}", out)
            self.assertFalse((out / "site.bin").exists())

    def test_does_not_follow_parent_symlink_replaced_after_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site, outside, out = root / "site", root / "outside", root / "out"
            (site / "sub").mkdir(parents=True)
            outside.mkdir()
            out.mkdir()
            (site / "sub" / "public.txt").write_text("public", encoding="utf-8")
            (outside / "public.txt").write_text("synthetic secret", encoding="utf-8")
            enumerate_site = pack.site_files

            def replace_parent_after_enumeration(path):
                result = enumerate_site(path)
                (site / "sub").rename(site / "saved")
                (site / "sub").symlink_to(outside, target_is_directory=True)
                return result

            with patch.object(pack, "site_files", side_effect=replace_parent_after_enumeration):
                with self.assertRaisesRegex(SystemExit, "cannot safely open sub/public.txt"):
                    self.pack(site, out)
            self.assertFalse((out / "site.bin").exists())


if __name__ == "__main__":
    unittest.main()
