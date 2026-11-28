#!/usr/bin/env python3
"""Keep TCP's SACK cursor out of live RTT and retransmission-timer fields."""
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def equ(name):
    for line in (ROOT / "src/os.asm").read_text().splitlines():
        match = re.match(r"\s*(C_\w+)\s+equ\s+([^;]+)", line)
        if match and match.group(1) == name:
            value = match.group(2).strip()
            try:
                return int(value, 0)
            except ValueError:
                return equ(value)
    raise AssertionError(f"missing {name} in src/os.asm")


class TCPStateLayout(unittest.TestCase):
    def test_sack_cursor_uses_only_unused_client_aes128_key_bytes(self):
        kiv = equ("C_KIV")
        sack = equ("C_SACK")
        client_key = kiv + 44
        unused_key_start = client_key + 16
        unused_key_end = client_key + 32

        self.assertGreaterEqual(sack, unused_key_start)
        self.assertLessEqual(sack + 4, unused_key_end)
        self.assertGreaterEqual(sack, equ("C_T0") + 4)
        self.assertGreaterEqual(sack, equ("C_RTO") + 1)


if __name__ == "__main__":
    unittest.main()
