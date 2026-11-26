#!/usr/bin/env python3
"""mksite.py DIR [BIG_MIB]: a site to test with. Always the same bytes: pages, a
stylesheet, a picture, files whose sizes sit on and around every boundary the server cuts
at (a record holds 194, 514, 1198 or 1418 bytes of a response, by the client's segment
size), a folder with an index, names that need escaping, an empty file, a 404 page, a
hidden file that must not be served, one large file (BIG_MIB, default 1.5 MiB), and text
that gets shorter when compressed: a stylesheet, and a long list (200 KB)."""
import hashlib
import os
import sys


def noise(tag, n):
    return b"".join(hashlib.sha256(b"%s %d" % (tag.encode(), i)).digest() for i in range(n // 32 + 1))[:n]


def main(root, big):
    files = {
        "index.html": b"<!doctype html>\n<title>k18 test site</title>\n<link rel=stylesheet href=css/style.css>\n"
                      b"<h1>Hello from a tiny HTTPS OS</h1>\n<img src=img/logo.svg>\n<a href=docs/>docs</a>\n",
        "css/style.css": b"body { font: 16px/1.5 sans-serif; margin: 3em auto; max-width: 40em }\n" * 40,
        "img/logo.svg": b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8" fill="#246"/></svg>\n',
        "docs/index.html": b"<!doctype html>\n<title>docs</title>\n<p>Documents.\n",
        "docs/a b.txt": b"a file whose name has a space\n",
        "docs/ünï.txt".encode().decode(): "ein Name mit Umlauten\n".encode(),
        "empty.txt": b"",
        "404.html": b"<!doctype html>\n<title>not here</title>\n<p>Nothing by that name.\n",
        ".hidden": b"must not be served\n",
        ".well-known/security.txt": b"Contact: mailto:security@example.org\n",
        "big.bin": noise("big", int(big * (1 << 20))),
        "mid.bin": noise("mid", 40000),
        "docs/list.txt": b"".join(b"%d: %s\n" % (i, hashlib.sha256(b"item %d" % i).hexdigest()[:24].encode()) for i in range(6600)),
    }
    for p in (194, 514, 1198, 1418):
        for n in (p - 1, p, p + 1, 2 * p - 1, 2 * p, 2 * p + 1, 10 * p, 10 * p + 1, 11 * p):
            files[f"size/{n}.bin"] = noise(f"size{n}", n)
    for n in (1, 2, 100, 2500, 14000, 15000, 70000):
        files[f"size/{n}.bin"] = noise(f"size{n}", n)
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path) or open(path, "rb").read() != data:
            with open(path, "wb") as f:
                f.write(data)
    print(f"{root}: {len(files)} files")


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 1.5)
