#!/usr/bin/env python3
"""Make an NSS certificate database that trusts one CA for TLS servers.

Usage: nssdb.py DIR CA_PEM
The same as `certutil -d sql:DIR -A -t C,, -n k2 -i CA_PEM`, for machines without
libnss3-tools: it calls libnss3 (which Chrome needs anyway) directly. Chrome on Linux reads
$HOME/.pki/nssdb for the roots a user added, so browsers.sh points HOME at a throwaway one.
"""
import base64
import ctypes
import os
import sys


class SECItem(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("data", ctypes.c_char_p), ("len", ctypes.c_uint)]


class CERTCertTrust(ctypes.Structure):
    _fields_ = [("ssl", ctypes.c_uint), ("email", ctypes.c_uint), ("objsign", ctypes.c_uint)]


def main(directory, ca_path):
    der = base64.b64decode("".join(l for l in open(ca_path).read().splitlines() if "-----" not in l))
    os.makedirs(directory, exist_ok=True)
    nss = ctypes.CDLL("libnss3.so")
    for name in ("PK11_GetInternalKeySlot", "CERT_GetDefaultCertDB", "CERT_NewTempCertificate"):
        getattr(nss, name).restype = ctypes.c_void_p
    if nss.NSS_InitReadWrite(f"sql:{directory}".encode()):
        sys.exit("nssdb.py: NSS_InitReadWrite failed")
    slot = ctypes.c_void_p(nss.PK11_GetInternalKeySlot())
    db = ctypes.c_void_p(nss.CERT_GetDefaultCertDB())
    if nss.PK11_NeedUserInit(slot):
        nss.PK11_InitPin(slot, None, b"")  # a new database: no password
    item = SECItem(0, der, len(der))
    cert = ctypes.c_void_p(nss.CERT_NewTempCertificate(db, ctypes.byref(item), None, 0, 1))
    if not cert:
        sys.exit("nssdb.py: NSS cannot parse the CA certificate")
    trust = CERTCertTrust()
    if (nss.PK11_ImportCert(slot, cert, 0, b"k2", 0)
            or nss.CERT_DecodeTrustString(ctypes.byref(trust), b"C,,")
            or nss.CERT_ChangeCertTrust(db, cert, ctypes.byref(trust))):
        sys.exit("nssdb.py: importing the CA failed")
    nss.CERT_DestroyCertificate(cert)
    nss.PK11_FreeSlot(slot)
    nss.NSS_Shutdown()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
