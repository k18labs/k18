#!/usr/bin/env python3
"""tlsfuzz.py SCRIPT [ARGS...]: one of tlsfuzzer's test scripts against a running image.

tlsfuzzer (github.com/tlsfuzzer/tlsfuzzer; `tools/outside.sh fetch` gets it into ext/) is
what TLS libraries are tested with from outside: some thousand conversations, most of
them wrong in one place, each with what a correct server answers. Its scripts take for
granted four things we don't do, so each would fail in its first lines. They are run
as they are, with those four things said here instead:

  - Their group is secp256r1, ours is x25519, and only two scripts can be told. So the
    two names change places: what a script calls secp256r1 is x25519 on the wire, and
    the other way round. (NOSWAP=1 in front: not so, for the scripts that are about
    the groups themselves.)
  - Most offer signatures of RSA only, for a server is to sign with what the client
    offers. We sign with ecdsa_secp256r1_sha256 whatever it offers, which every client
    of TLS 1.3 has: here every client says so too.
  - A server is to send a ChangeCipherSpec record after its first handshake message,
    for middleboxes' sake. Ours comes after the ServerHello, also where a
    HelloRetryRequest went before it (docs/internals.md, "Shortcuts that remain"). So
    here, as in a client, the server's is passed over wherever it comes before its
    EncryptedExtensions, and one has to have come by then.
  - Where a server is to answer with an alert and close, we pass over what we can't
    use and say nothing. So an alert or a close that is waited for may also be QUIET
    seconds (0.3) of silence; and an alert may be the connection's end with nothing
    said (a record of the client's with no content type in it: our FIN). Anything else
    that comes instead still fails, and an alert that does come must be the one the
    script wants. The last line says how often an alert was waited for, how often one
    came, and how often the connection's end came in its place.

    tools/tlsfuzz.py test-tls13-conversation -h 10.0.2.15 -p 443

tools/tlsfuzz.sh runs the scripts that apply to us and says what each is expected to do.
"""
import importlib
import io
import os
import re
import socket
import sys

EXT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ext")
sys.path[:0] = [os.path.join(EXT, "py"), os.path.join(EXT, "tlsfuzzer")]
from tlslite.constants import ContentType, GroupName, SignatureScheme  # noqa: E402
from tlslite.extensions import SignatureAlgorithmsExtension  # noqa: E402
from tlsfuzzer.messages import Command, Connect  # noqa: E402
import tlsfuzzer.expect as expect  # noqa: E402

QUIET = float(os.environ.get("QUIET", "0.3"))
WAIT = float(os.environ.get("WAIT", "1.5"))     # (for anything else; tlsfuzzer waits 5 s)
count = {"waited": 0, "came": 0, "closed": 0}


class Groups(object):
    """tlslite's GroupName as a script is to see it: the two names changed places."""
    secp256r1, x25519 = GroupName.x25519, GroupName.secp256r1

    def __getattr__(self, name):
        return getattr(GroupName, name)


class PassedOver(Command):
    """Where a script waits for the server's ChangeCipherSpec: nothing. It is passed over
    when it comes (`Impatient`), and `AfterOne` asks whether it did."""

    def process(self, state):
        pass


class AfterOne(expect.ExpectEncryptedExtensions):
    """The server's EncryptedExtensions, which a ChangeCipherSpec has to have come before."""

    def process(self, state, msg):
        if not getattr(state.msg_sock, "passed", 0):
            raise AssertionError("no ChangeCipherSpec came before the server's EncryptedExtensions")
        state.msg_sock.passed = None    # (from here on one is not passed over)
        return super(AfterOne, self).process(state, msg)


class AlertOrSilence(expect.ExpectClose, expect.ExpectNoMessage):
    """The alert the script wants, or nothing for QUIET seconds, or the connection's end
    (the runner then comes here with no message, as to an ExpectClose)."""

    def __init__(self, level=None, description=None):
        super(AlertOrSilence, self).__init__()
        self.alert = Alert(level, description)
        self.content_type = self.alert.content_type
        self.level, self.description = level, description

    @property
    def timeout(self):                  # (the runner asks when it gets here)
        count["waited"] += 1
        return QUIET

    @timeout.setter
    def timeout(self, _):
        pass

    def is_match(self, msg):
        return self.alert.is_match(msg)

    def process(self, state, msg):
        if msg is None:
            count["closed"] += 1
            return None
        count["came"] += 1
        return self.alert.process(state, msg)


class TicketOrSilence(expect.ExpectNoMessage):
    """A NewSessionTicket (scripts wait for any number of them, and we send none), where a
    script waits for those or for an alert: then silence is what the alert may be."""

    def __init__(self, *args, **kwargs):
        super(TicketOrSilence, self).__init__(WAIT)
        self.ticket = Ticket(*args, **kwargs)
        self.content_type = self.ticket.content_type
        self.asked = False

    def alert(self):
        return next((n for n in self.get_all_siblings() if isinstance(n, AlertOrSilence)), None)

    @property
    def timeout(self):
        self.asked = True
        return QUIET if self.alert() else WAIT

    @timeout.setter
    def timeout(self, _):
        pass

    def is_match(self, msg):
        self.asked = False              # (something came)
        return self.ticket.is_match(msg)

    def process(self, state, msg):
        return self.ticket.process(state, msg)

    @property
    def child(self):
        if not self.asked or not isinstance(sys.exc_info()[1], socket.timeout):
            return self.then
        self.asked = False              # (nothing came: on as if the alert had)
        if not self.alert():
            raise AssertionError("Timeout when waiting for peer message")
        count["waited"] += 1
        return self.alert().child

    @child.setter
    def child(self, node):
        self.then = node


class CloseOrSilence(expect.ExpectClose, expect.ExpectNoMessage):
    def __init__(self):
        super(CloseOrSilence, self).__init__()
        self.timeout = QUIET


class WithOurs(SignatureAlgorithmsExtension):
    """What the client says it can verify, and ecdsa_secp256r1_sha256 if that is not in it."""

    def create(self, sigalgs):
        ours = SignatureScheme.ecdsa_secp256r1_sha256
        return super(WithOurs, self).create(list(sigalgs) + [ours] * (ours not in sigalgs))


class Impatient(Connect):
    """Waits less long; and passes over the server's ChangeCipherSpec records, as a client
    is to at any time before the server's Finished (RFC 8446, 5): here, before its
    EncryptedExtensions, and counted."""

    def __init__(self, hostname, port, version=(3, 0), timeout=WAIT):
        super(Impatient, self).__init__(hostname, port, version, timeout)

    def process(self, state):
        super(Impatient, self).process(state)
        sock = state.msg_sock
        theirs, sock.passed = sock.recvMessageBlocking, 0

        def recv():
            while True:
                header, parser = theirs()
                if (header.type != ContentType.change_cipher_spec or sock.passed is None
                        or bytes(parser.bytes) != b"\x01"):
                    return header, parser
                sock.passed += 1
        sock.recvMessageBlocking = recv


Alert, Ticket = expect.ExpectAlert, expect.ExpectNewSessionTicket
name = sys.argv[1].replace(".py", "").replace("-", "_")
sys.argv = sys.argv[1:]
script = importlib.import_module("tlsfuzzer._apps." + name)
for theirs, ours in (("ExpectChangeCipherSpec", PassedOver), ("ExpectEncryptedExtensions", AfterOne),
                     ("ExpectAlert", AlertOrSilence), ("ExpectClose", CloseOrSilence),
                     ("ExpectNewSessionTicket", TicketOrSilence), ("SignatureAlgorithmsExtension", WithOurs),
                     ("Connect", Impatient)) + ((("GroupName", Groups()),) if not os.environ.get("NOSWAP") else ()):
    if hasattr(script, theirs):         # (the names as the script has them; tlsfuzzer's own stay)
        setattr(script, theirs, ours)


class Tee(io.TextIOBase):
    def __init__(self, to):
        self.to, self.text = to, []

    def write(self, text):
        self.text.append(text)
        return self.to.write(text)

    def flush(self):
        self.to.flush()


out = sys.stdout = Tee(sys.stdout)
try:
    script.main()
    code = 0
except SystemExit as e:
    code = e.code
sys.stdout = out.to
# ALLOW=regex: the conversations that are expected to fail (their names begin so); with
# it, the verdict is whether any other failed.
text = "".join(out.text)
failed = re.findall(r"^\t'(.*)'$", text.split("FAILED:")[1], re.M) if "FAILED:" in text else []
total = re.search(r"^TOTAL: (\d+)", text, re.M)
if os.environ.get("ALLOW") is not None and total:
    allow = os.environ["ALLOW"]
    other = sorted(set(f for f in failed if not (allow and re.match(allow, f))))
    code = 1 if other else 0
    for f in other[:20]:
        print("NOT EXPECTED TO FAIL: %s" % f)
print("%s: %s conversations, %d failed%s; an alert was waited for %d times and came %d times%s"
      % (name.replace("_", "-"), total.group(1) if total else "no", len(failed),
         " as expected" if failed and not code else "", count["waited"], count["came"],
         ", the connection's end %d times" % count["closed"] if count["closed"] else ""))
sys.exit(code)
