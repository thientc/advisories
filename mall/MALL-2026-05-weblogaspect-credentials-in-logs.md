# MALL-2026-05: Passwords, verification codes and JWTs written to the application log

- Product: macrozheng/mall (https://github.com/macrozheng/mall)
- Reporter: thientc (VinSOC)
- Vendor status: no private reporting channel (GitHub private vulnerability reporting disabled, no SECURITY.md); vendor notified on 2026-11-18 via public GitHub issue https://github.com/macrozheng/mall/issues/1042 (contact request, no technical details), no reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`WebLogAspect` in mall-common logs every controller call with its full arguments and return value, at INFO level and without masking. Passwords sent to `/sso/login` and `/admin/login`, the verification code returned by `/sso/getAuthCode`, and the JWT returned by a successful login all end up in cleartext in the application log and in anything that ships it (the bundled logstash appender, for example).

## Details

The pointcut covers every public method of `com.macro.mall.controller.*` and `com.macro.mall.*.controller.*` (`mall-common/src/main/java/com/macro/mall/common/log/WebLogAspect.java:42`). For each call the aspect builds a `WebLog`:

```java
// WebLogAspect.java:76-77
webLog.setParameter(getParameter(method, joinPoint.getArgs()));
webLog.setResult(result);
```

`getParameter` (`:96-125`) collects every `@RequestParam` and `@RequestBody` argument. The whole object is then written with `LOGGER.info(Markers.appendEntries(logMap), JSONUtil.parse(webLog).toString())` (`:89`). Nothing filters keys such as `password`, `authCode` or `token`.

## PoC

Send a login with a recognisable password and watch the log (portal on 8085, admin on 8080; the accounts don't need to exist):

```sh
curl -s -X POST "$PORTAL/sso/login" -d username=nobody1 -d password=MARKER-portal-1
curl -s "$PORTAL/sso/getAuthCode?telephone=19900003301"
curl -s -X POST "$ADMIN/admin/login" -H 'Content-Type: application/json' \
  -d '{"username":"nobody2","password":"MARKER-admin-2"}'
docker compose logs mall-portal mall-admin | grep -E 'MARKER-|19900003301'
```

The portal log line reads `WebLogAspect : {"description":"会员登录",...,"uri":"/sso/login",...,"parameter":[{"username":"nobody1"},{"password":"MARKER-portal-1"}],...}`. The `getAuthCode` line has the generated code in `result`, and the admin line has `"password":"MARKER-admin-2"`. For a successful member login, both the password and the issued JWT appear in the same line. Before the requests, the markers did not occur in the logs. (The marker strings above are illustrative; my lab run used different ones.)

## Impact

Anyone who can read the application logs gets working member and admin passwords, valid session tokens (7-day lifetime) and fresh verification codes for password reset. That includes operators, log pipeline or Elasticsearch users, and whoever gets hold of a log backup. The reader needs privileged access to the logs, so this is a credential-exposure issue rather than a remote one, and I scored it accordingly.

Suggested fix: mask sensitive keys (`password`, `authCode`, `token` and similar) in both the parameters and the result before logging, or skip the aspect on authentication endpoints. I tested a URI-based redaction on a patched build: the marker passwords and the JWT no longer appear and other requests are still logged. A key-based filter would be more complete, since `/admin/update` still logs the (bcrypt-hashed) password with the URI approach.

## Affected versions

- Tested and affected: master at commit dcaa93b (`master-dcaa93b`).
- `WebLogAspect` is the same in the v1.0.3 tag; I read it but did not run it there.
- Fixed in: no fixed release was known when this report was drafted.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: master-dcaa93b.

## Severity

CVSS 3.1 base score **4.4** (Medium): `CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`

- **AV:L / PR:H** The secrets are read from the log store, which needs privileged access, not over the application's interface.
- **AC:L / UI:N** Every normal login writes them; no victim action beyond logging in.
- **S:U** Same application trust zone.
- **C:H** Cleartext passwords, valid tokens and reset codes.
- **I:N / A:N** No direct effect by itself.

## Credit

thientc (VinSOC)
