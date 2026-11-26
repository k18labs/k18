#!/usr/bin/env python3
"""Print the certificate error flags Chrome recorded for HOST in a net-log; exit 1 if there are any.
Usage: certerr.py NETLOG HOST"""
import json
import sys

ERRORS = {"COMMON_NAME_INVALID", "DATE_INVALID", "AUTHORITY_INVALID", "NO_REVOCATION_MECHANISM",
          "UNABLE_TO_CHECK_REVOCATION", "REVOKED", "INVALID", "WEAK_SIGNATURE_ALGORITHM",
          "NON_UNIQUE_NAME", "WEAK_KEY", "PINNED_KEY_MISSING", "NAME_CONSTRAINT_VIOLATION",
          "VALIDITY_TOO_LONG", "CERTIFICATE_TRANSPARENCY_REQUIRED", "SYMANTEC_LEGACY",
          "KNOWN_INTERCEPTION_BLOCKED", "CONTAINS_ERRORS"}
raw = open(sys.argv[1]).read()
try:
    d = json.loads(raw)
except ValueError:
    d = json.loads(raw.rstrip().rstrip(",") + "]}")
names = {v: k for k, v in d["constants"].get("certStatusFlag", {}).items()}
local = {e["source"]["id"] for e in d["events"] if sys.argv[2] in json.dumps(e.get("params", {}))}
flags, seen = set(), False
for e in d["events"]:
    st = e.get("params", {}).get("cert_status")
    if e["source"]["id"] in local and st is not None:
        seen = True
        flags |= {n for f, n in names.items() if st & f}
print(" ".join(sorted(flags)) or ("none" if seen else "no certificate seen"))
sys.exit(1 if not seen or flags & ERRORS else 0)
