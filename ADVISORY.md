# Security Advisory — D-Link DIR-868L B1 e-mail settings / MYDLINKMAIL command injection

| Field | Value |
|---|---|
| Title | Unauthenticated OS command injection in the D-Link DIR-868L B1 e-mail settings handler (`form_emailsetting` → `MYDLINKMAIL.php`) leads to root code execution |
| Affected vendor | D-Link |
| Affected product | DIR-868L, hardware revision B1 |
| Affected firmware | v2.03b01 (`DIR868LB1_FW203b01.bin`, SHA-256 `9af5829b628d6274f4a7fe8f3926aaa7cc51760579aa4fa117c384f96b44a2c5`) — dynamically verified |
| Also contains the same vulnerable files | v2.01b05 and 2.05-family builds (2.05, 2.05WW, 2.05b01): byte-identical `form_emailsetting`, `MYDLINKMAIL.php`, `header.php` (static comparison; not dynamically verified) |
| Vulnerable components | `/htdocs/mydlink/form_emailsetting`, `/etc/scripts/mydlink/MYDLINKMAIL.php`, `/goform` (phpcgi), `MYDLINK_TESTMAIL` event chain (`mdtestmail` → `mydlinkeventd` → `phpsh`) |
| Weakness | CWE-78 (primary); CWE-863 / CWE-93 as the authentication-bypass access vector |
| CVSS 3.1 | **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Attack vector | Network, **pre-authentication**, no user interaction (1 GET + 1 POST), root command execution with output read-back |
| CVE | pending (VulDB submission, 2026-11-22) |
| Public repository | https://github.com/Walnut1337/DIR-868L-Email-RCE |

## 1. Summary

The DIR-868L B1 web interface exposes the e-mail settings/test handler at
`/goform/form_emailsetting` (phpcgi → `/htdocs/cgibin`, ePHP). The handler
copies the attacker-controlled `config.smtp_email_from_email_addr` value into
`/device/log/email/from` and, when `config.smtp_email_action=true`, fires the
`MYDLINK_TESTMAIL` event. The event chain (`mdtestmail` → `mydlinkeventd` →
`phpsh /etc/scripts/mydlink/MYDLINKMAIL.php`) renders the stored value into an
**unquoted** shell command line (`$username = $from;`):

```php
if ($authenable != "0") {
    echo 'email'. ' -V '. ' -f '.$from. ' -n '.$displayfrom. ...
         ' -u '.$username. ' -i '.$password. ...;
} else {
    echo 'email'. ' -V '. ' -f '.$from. ' -n '.$username. ...;
}
```

Observed rendered line (the payload is in `-f`; the trailing `#` comments out
the rest, including the second `$from` in `-u`):

    email -V  -f a;cd /var/htdocs/upnp/LAN-1;exec >out.gif 2>&1;<command>;# -n mydlink ... -u a;...# -i ...

`/usr/sbin/phpsh` executes that line as **root**. A value such as
`a;cd /var/htdocs/upnp/LAN-1;exec >out.gif 2>&1;<command>;#` therefore runs
arbitrary commands as root.

The handler is protected by `header.php`:

```php
if($AUTHORIZED_GROUP>=0) { echo "HTTP/1.1 200 OK\n"; ... } else { exit; }
```

phpcgi URL-decodes the query string (`%0a` → newline) and the xmldb ePHP
engine is **FIRST-WINS** on duplicate globals, so

```
GET /goform/form_emailsetting?x=AAA%0aAUTHORIZED_GROUP=0
```

inserts a forged `AUTHORIZED_GROUP=0` line ahead of the real one and turns the
gate's `500` into `200`. The same unauthenticated POST then writes the payload
and fires the event.

The command-injection sink is **independent of the gate bypass**: an
authenticated administrator can reach the same handler and the same sink
(post-auth root RCE). The gate bypass is a known primitive on this model
(CVE-2019-17506, different endpoint); the e-mail handler command injection
reported here is not covered by that CVE.

## 2. Affected entry point

| Interface | Endpoint | Notes |
|---|---|---|
| LAN web UI (port 80) | `GET/POST /goform/form_emailsetting` | `/goform` → `/htdocs/mydlink`, `PathInfo On`, `External /usr/sbin/phpcgi { * }` |
| LAN web UI | `?x=AAA%0aAUTHORIZED_GROUP=0` | gate bypass (query value newline injection) |
| Event chain | `MYDLINK_TESTMAIL` | registered at boot by `/etc/init0.d/S43mydlinkevent.sh` when `/device/layout=="router"` (factory default) |
| Output | `http://TARGET:49152/<mark>.gif` | `/var/htdocs/upnp/LAN-1` is served by the UPnP LAN vhost |

## 3. Root cause

1. **Template line injection in phpcgi.** The phpcgi handler builds an ePHP
   template from the request, writing one `_GET_<k>=<v>` line per query
   parameter after `%XX` decoding. A value containing `%0a` emits a new
   `KEY=VALUE` line. (The same primitive is used by CVE-2019-17506 against
   `getcfg.php`.)
2. **FIRST-WINS duplicate globals in xmldb.** The parser appends duplicate
   names at the tail of the variable list and lookups walk from the head, so
   the injected `AUTHORIZED_GROUP=0` beats the real `AUTHORIZED_GROUP=<n>`
   appended later.
3. **The gate trusts a single global.** `header.php` only checks
   `$AUTHORIZED_GROUP>=0`; there is no separate authentication before the
   script is rendered.
4. **Unquoted e-mail argument.** `MYDLINKMAIL.php` concatenates the stored
   `from` value directly into the `email -V -f <from> ...` shell line without
   quoting or escaping; `phpsh` runs the rendered script as root.
5. **No validation at the write side.** `form_emailsetting` stores
   `config.smtp_email_from_email_addr` verbatim.

Static comparison shows `form_emailsetting`, `MYDLINKMAIL.php` and
`header.php` are byte-identical in 2.01b05, 2.03b01 and the 2.05-family builds:

| File | SHA-256 |
|---|---|
| `htdocs/mydlink/form_emailsetting` | `e9baf8a1a06c9c28eb3792ca15bff0ad78a7621ec63d8cc12c771de48d031127` |
| `etc/scripts/mydlink/MYDLINKMAIL.php` | `b64d0ae2caddc8fb110d2b68473b49223269a9ffe37aa53c00cccfef71ef10ee` |
| `htdocs/mydlink/header.php` | `802c8f848e102593f5587e7f8da196293ac58811f608cfe6179e96bb52ffedaf` |

## 4. Impact

Unauthenticated remote code execution as **root** on the router, with output
read-back:

- read/write configuration (NVRAM, `/device`), credentials (`/etc/shadow`),
  firmware and boot environment;
- persistence, LAN pivoting, router takeover;
- the same sink is reachable by an authenticated administrator, so fixing only
  the authentication gate would not remove the command injection.

## 5. Verification

### 5.1 Physical unit (FW 2.03b01, LAN-side)

| Check | Result |
|---|---|
| Identity | MAC `E4:6F:13:3E:AE:04`, HTTP `Date` 2026-11-21, `uname` `Linux dlinkrouter 2.6.36.4brcmarm+` |
| Gate | `GET /goform/form_emailsetting` → `500`; `?x=AAA%0aAUTHORIZED_GROUP=0` → `200` |
| Exploit POST | `200 test ok` (no cookie/session) |
| Evidence file | `r357_full.gif`, 1008 B, MD5 `839be6ae5c79a0b03e950f88d40dd2d6` |
| Content | `Uid: 0 0 0 0`, `CapEff ffffffffffffffff`, `/etc/passwd`, `/etc/shadow` (`root:!:20778`, `Admin:<redacted>`) |
| Retrieval | `GET http://TARGET:49152/r357_full.gif` |
| Re-verification 2026-11-22 | MAC `E4:6F:13:3E:AE:04`, FW 2.03; gate `500` → `200`; POST `200 test ok`; `Uid: 0 0 0 0`, `CapEff ffffffffffffffff`, `uname` `2.6.36.4brcmarm+`, `/etc/shadow` `root:!:20778` (see `evidence/physical_reverify_redacted.txt`) |

### 5.2 FirmAE (IID=7, full-system, FW 2.03b01)

| Check | Result |
|---|---|
| Gate | `500` → `200` with the injected query |
| Exploit POST | `200 test ok` |
| Command output | `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, `CapEff 0000003fffffffff`, `uname` 4.1.17, `root:!:10957` in `/etc/shadow` |
| Output evidence | `/var/htdocs/upnp/LAN-1/d868ag0_*.gif` served on `:49152` |

### 5.3 PoC

```bash
python3 poc_DIR868L_AG0_RCE.py 192.168.0.1 'cat /proc/self/status; cat /etc/shadow'
```

The PoC performs the gate check, the POST, polls
`http://TARGET:49152/<mark>.gif`, prints the output and restores the e-mail
baseline (`enable=0`, `from/to/subject/server/...` empty, evidence removed).

## 6. Related vulnerabilities (not duplicates)

| CVE / report | Relation |
|---|---|
| **CVE-2019-17506** | Same `AUTHORIZED_GROUP` newline-injection primitive on DIR-868L B1-2.03, but against `getcfg.php` and resulting in credential disclosure. Different endpoint and impact; the command injection reported here is also reachable post-auth and is not covered by it. |
| CVE-2018-19987 / CVE-2018-19988 | HNAP `SetAccessPointMode` / `SetClientInfoDemo` command injection on DIR-868L Rev.B 2.05B02 — different handlers and sinks. |
| CVE-2026-110536 | HNAP `SOAPACTION` command injection on DIR-868L 2.01b05 — different handler. |
| CVE-2025-14659 | DHCP hostname command injection on DIR-860L/868L B1 203b01/203b03 — different daemon. |
| CVE-2026-3485 | SSDP `ST` command injection on DIR-868L 110b03 — different entry point. |
| CVE-2025-55583 | `fileaccess.cgi` `pre_api_arg` command injection on DIR-868L B1 2.05WWB02 — different component. |
| CVE-2023-32153 / CVE-2023-44422 / CVE-2025-60701 | E-mail-field command injection on other D-Link models (DIR-2640 `EmailFrom`, DIR-X3260 `SetSysEmailSettings`, DIR-882 `EmailTo`/`SMTPServerAddress`). Same class, different product/code. |

## 7. Remediation

1. Do not build shell command lines from configuration values. Invoke the
   mailer with an argv array (`execve`) and pass `from`/`to`/subject as
   separate arguments.
2. If a shell is unavoidable, quote every value (`escapeshellarg`) and reject
   control characters and shell metacharacters in `form_emailsetting`.
3. Remove the privileged `phpsh` shell rendering for mail/event scripts.
4. Fix the authorization design: namespace `AUTHORIZED_GROUP`, reject
   duplicate globals (or make them LAST-WINS), reject `\r`/`\n` in query
   values, and authenticate before rendering `/goform` scripts.
5. The DIR-868L is end-of-life (D-Link SAP10397); replace the device.

## 8. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-21 | End-to-end verification on the physical unit (FW 2.03b01) |
| 2026-11-22 | Full-system and static verification, duplicate check, VulDB submission |

## 9. Repository layout

| Path | Content |
|---|---|
| `poc/poc_DIR868L_AG0_RCE.py` | one-shot PoC (gate check, POST, read-back, cleanup) |
| `analysis/root_cause.md` | technical deep dive (phpcgi/ePHP, event chain, unquoted mailer) |
| `evidence/gate_plain_500.http` | control response |
| `evidence/gate_bypass_200.http` | gate-bypass response |
| `evidence/root_rce_output_redacted.txt` | root command output (credential hashes redacted) |
| `evidence/physical_r357_redacted.txt` | physical-unit evidence (credential hashes redacted) |
| `evidence/hashes.txt` | firmware / component SHA-256 |

## 10. Credit

Discovered and researched by **`Walnut1337`** (`walnut1337@163.com`), 2026-11.
