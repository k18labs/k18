#!/usr/bin/env python3
"""Load a URL in headless Firefox via Marionette and report what rendered, then quit cleanly.

Usage: ffcheck.py URL CA_PEM EXPECTED-TEXT
Uses a throwaway profile. If CA_PEM is not empty, that CA is put into the profile as a
trusted root first (tools/nssdb.py; what Settings > Certificates > Import does). There are
no certificate exceptions, so
the page only loads if Firefox accepts the chain and the name. Prints the error page's code
otherwise. Exit 0 only if EXPECTED-TEXT shows up. A name that is not an IP address is
resolved to 127.0.0.1 (the tests' servers are there), unless REALDNS=1 says the name is
a real one. Unlike --screenshot, this never leaves Firefox hanging on an error page.

If Firefox is a snap, its binary is started directly: the snap launcher needs privileges
that sandboxes (and some desktop apps' terminals) don't pass on, and a Firefox started
through it can't be killed from there either. FIREFOX=/path/to/firefox overrides.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

url, ca_path, expect = sys.argv[1], sys.argv[2], sys.argv[3]
SNAP = "/snap/firefox/current/usr/lib/firefox/firefox"
firefox = os.environ.get("FIREFOX") or (SNAP if os.path.exists(SNAP) else "firefox")
host = urllib.parse.urlsplit(url).hostname
mport = 2900 + os.getpid() % 500

# under build/: snap Firefox can't read the host's /tmp
prof = tempfile.mkdtemp(prefix="ffcheck.", dir=os.path.join(os.path.dirname(__file__), "..", "build"))
if os.path.getsize(ca_path):
    subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(__file__), "nssdb.py"), prof, ca_path], check=True)
with open(os.path.join(prof, "user.js"), "w") as f:
    f.write(f'user_pref("marionette.port", {mport});\n'
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
            + ("" if host.replace(".", "").isdigit() or os.environ.get("REALDNS") else f'user_pref("network.dns.localDomains", "{host}");\n'))

ff = subprocess.Popen([firefox, "--headless", "--marionette", "-no-remote", "-profile", prof],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def connect():
    for _ in range(100):
        try:
            return socket.create_connection(("127.0.0.1", mport), timeout=20)
        except OSError:
            time.sleep(0.2)
    raise SystemExit("ffcheck: marionette did not come up")


sock = connect()
buf = b""


def recv():
    global buf
    while b":" not in buf:
        buf += sock.recv(65536)
    n, rest = buf.split(b":", 1)
    n = int(n)
    while len(rest) < n:
        rest += sock.recv(65536)
    buf = rest[n:]
    return json.loads(rest[:n])


msgid = 0


def cmd(name, params=None):
    global msgid
    msgid += 1
    data = json.dumps([0, msgid, name, params or {}]).encode()
    sock.sendall(str(len(data)).encode() + b":" + data)
    while True:
        m = recv()
        if m[0] == 1 and m[1] == msgid:
            return m[2], m[3]  # error, result


try:
    recv()  # server hello
    cmd("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": False}}})
    cmd("WebDriver:SetTimeouts", {"pageLoad": 12000})
    err, _ = cmd("WebDriver:Navigate", {"url": url})
    _, res = cmd("WebDriver:ExecuteScript", {"script": "return [document.documentURI, document.body ? document.body.innerText : '']", "args": []})
    if not res:
        print(f"firefox: no page (navigate: {err and err.get('error')}: {(err or {}).get('message', '')[:300]}; script: {_ and str(_)[:200]})")
        sys.exit(1)
    uri, text = res["value"]
    if uri.startswith("about:"):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
        _, res = cmd("WebDriver:ExecuteScript", {"script": "try { return document.getFailedCertSecurityInfo().errorCodeString } catch (e) { return String(e) }", "args": []})
        print(f"firefox: ERROR PAGE {uri.split('?')[0]} e={q.get('e')} code={res.get('value')!r}"
              + (f" navigate={err.get('error')}" if err else ""))
        ok = False
    else:
        print(f"firefox: page text {text[:60]!r}")
        ok = expect in text
    try:
        cmd("Marionette:Quit", {"flags": ["eForceQuit"]})
    except OSError:
        pass
finally:
    try:
        ff.wait(timeout=15)
    except subprocess.TimeoutExpired:
        ff.kill()
    shutil.rmtree(prof, ignore_errors=True)
sys.exit(0 if ok else 1)
