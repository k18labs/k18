#!/usr/bin/env python3
"""Test helper: make a certificate chain shaped like a real one, to try the drop-in path.

Usage: mkchain.py DIR [NAME]     (default NAME: k2.test)
Writes DIR/server.key, DIR/server.pem (leaf + intermediate) and DIR/ca.pem (the root), with
the sizes and extensions of a typical public ECDSA chain: a P-256 leaf of about 1 KB signed
by a P-384 intermediate of about 1 KB. Build and test with it like this:

    make B=build-real CERT=DIR && B=build-real CERT=DIR ./measure.sh

A chain from a public CA goes into a directory the same way, just without ca.pem (clients
then use their own root stores).
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def name(cn, org="K2 Test Trust Services"):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, pub, issuer, issuer_key, issuer_pub, days, ca, extra=()):
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), critical=False))
    for ext in extra:
        b = b.add_extension(ext, critical=False)
    return b.sign(issuer_key, hashes.SHA384())


def main(directory, host="k2.test"):
    os.makedirs(directory, exist_ok=True)
    root_key, mid_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root_name, mid_name = name("K2 Test Root X1"), name("K2 Test Intermediate E7")
    root = cert(root_name, root_key.public_key(), root_name, root_key, root_key.public_key(), 7300, True)
    info = [x509.AuthorityInformationAccess([x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://x1.i.k2.test/"))]),
            x509.CRLDistributionPoints([x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://x1.c.k2.test/42.crl")], None, None, None)]),
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), None)]),
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])]
    mid = cert(mid_name, mid_key.public_key(), root_name, root_key, root_key.public_key(), 3650, True, info)
    leaf = cert(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]), leaf_key.public_key(), mid_name,
                mid_key, mid_key.public_key(), 90, False, info + [
                    x509.SubjectAlternativeName([x509.DNSName(host)]),
                    # as big as two signed certificate timestamps
                    x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), os.urandom(242))])
    pem = serialization.Encoding.PEM
    with open(f"{directory}/server.key", "wb") as f:
        f.write(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(f"{directory}/server.pem", "wb") as f:
        f.write(leaf.public_bytes(pem) + mid.public_bytes(pem))
    with open(f"{directory}/ca.pem", "wb") as f:
        f.write(root.public_bytes(pem))
    print(f"{directory}: leaf {len(leaf.public_bytes(serialization.Encoding.DER))} bytes,"
          f" intermediate {len(mid.public_bytes(serialization.Encoding.DER))} bytes, for {host}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
