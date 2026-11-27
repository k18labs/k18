"""Security regressions for rawc's VIA neighbor lookup."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RawcViaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="rawc via ")
        cls.root = Path(cls.tmp.name)
        cls.bin_dir = cls.root / "bin"
        cls.bin_dir.mkdir()
        cls.fake_ip = cls.bin_dir / "test ip"
        cls.fake_ip.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['K18_TEST_IP_ARGS'], 'w') as f:\n"
            "    json.dump(sys.argv[1:], f)\n"
            "print('10.0.0.1 dev test0 lladdr 02:00:00:00:00:01 REACHABLE')\n",
            encoding="utf-8",
        )
        cls.fake_ip.chmod(0o755)
        cls.binary = cls.root / "rawc"
        subprocess.run(
            [
                "gcc",
                "-O2",
                f'-DK18_IP_PATH="{cls.fake_ip}"',
                "-o",
                str(cls.binary),
                str(ROOT / "tools" / "rawc.c"),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_rawc(self, via=None, guest="10.0.0.1"):
        case = Path(tempfile.mkdtemp(dir=self.root))
        (case / "page80.bin").write_bytes(b"x")
        args_file = case / "ip-args.json"
        marker = case / "shell-ran"
        env = os.environ.copy()
        env.update(
            {
                "B": str(case),
                "GUEST": guest,
                "TAP": "k18-test-interface-does-not-exist",
                "K18_TEST_IP_ARGS": str(args_file),
                "PATH": f"{self.bin_dir}:{env.get('PATH', '')}",
                "K18_TEST_MARKER": str(marker),
            }
        )
        if via is None:
            env.pop("VIA", None)
        else:
            env["VIA"] = via
        result = subprocess.run([str(self.binary), "1"], env=env, capture_output=True, text=True)
        return result, args_file, marker

    def test_valid_via_is_passed_as_one_argument(self):
        result, args_file, _ = self.run_rawc(via="10.0.0.1")
        self.assertTrue(args_file.exists(), result.stderr)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(args_file.read_text()), ["neigh", "show", "10.0.0.1"])

    def test_guest_fallback_remains_valid(self):
        result, args_file, _ = self.run_rawc(guest="10.0.0.2")
        self.assertTrue(args_file.exists(), result.stderr)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(args_file.read_text()), ["neigh", "show", "10.0.0.2"])

    def test_shell_syntax_in_via_is_rejected_without_running_a_command(self):
        result, args_file, marker = self.run_rawc(via="127.0.0.1; touch $K18_TEST_MARKER")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("invalid VIA IPv4 address", result.stderr)
        self.assertFalse(args_file.exists())
        self.assertFalse(marker.exists())

    def test_shell_syntax_in_guest_fallback_is_rejected(self):
        result, args_file, marker = self.run_rawc(guest="127.0.0.1; touch $K18_TEST_MARKER")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("invalid VIA IPv4 address", result.stderr)
        self.assertFalse(args_file.exists())
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
