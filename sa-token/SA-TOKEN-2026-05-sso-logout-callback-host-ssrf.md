# SA-TOKEN-2026-05: SSO logout callback is built from the Host header and fetched by the SSO server without validation (blind SSRF)

- Product: dromara/Sa-Token (https://github.com/dromara/Sa-Token)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-17 through GitHub private vulnerability reporting, [GHSA-g4g9-mxgm-fqcg](https://github.com/dromara/Sa-Token/security/advisories/GHSA-g4g9-mxgm-fqcg); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

When an SSO client has `reg-logout-call: true` and neither `curr-sso-logout-call` nor `curr-domain` is set, the client builds its logout callback URL from the incoming request URL, which comes from the `Host` header. It sends that URL to the SSO server inside the signed checkTicket message. The server stores it without any check, and on signout sends a GET to it.

Any SSO user can therefore make the SSO server request `http://<any host:port>/sso/logoutCall?...`. This is the configuration the docs give for anonymous clients (`sso/anon-client.md`).

## Details

v1.46.0 (`ae58d1cc`), under `sa-token-plugin/sa-token-sso/src/main/java/cn/dev33/satoken/sso/`:

- **Client:** `processor/SaSsoClientProcessor.java:324-333` runs:

  ```java
  ssoLogoutCall = SaHolder.getRequest().getUrl().replace(currUri, apiName.ssoLogoutCall);
  ```

  `getUrl()` is `request.getRequestURL()`, so the host and port are whatever the request's `Host` header says.

  The client signs the message itself (`template/SaSsoClientTemplate.java:217`), so the attacker never needs a secret.
- **Server:**
  - `message/handle/server/SaSsoMessageCheckTicketHandle.java:61-68` registers the callback.
  - `template/SaSsoServerTemplate.java:551-583` stores it.
  - Unlike the login redirect, it is never compared with allow-url.
  - On signout (`:624-637`), or when more than `maxRegClient` (32) entries evict the oldest (`:567-574`), the server calls `strategy.sendRequest.apply(finalUrl)` (`:685`), which is a plain `SaHttpTemplate.get`.

## PoC

Local lab only: Spring Boot 3.5.16, sa-token-sso and sa-token-rest-template 1.46.0 built from the tag. The client config is the same as the anon-client demo (`is-http: true`, `reg-logout-call: true`, no `curr-sso-logout-call`). Two HTTP listeners run on the internal Docker network. I used a test account.

1. The attacker logs in at the server and takes a ticket from `/sso/auth?redirect=http://client05.lab:19021/sso/login`.
2. ```
   GET http://client05.lab:19021/sso/login?ticket=<T>
   Host: l05-listener:8080
   ```
   This returns 302 (login ok).
3. As the attacker, call `GET /sso/signout` on the server. It returns `{"code":200,"msg":"单点注销成功"}`.

The listener logs a request from the SSO server's container IP:

```
GET /sso/logoutCall?autoLogout=false&loginId=10001&nonce=ZLZ7PZ...&sign=4b28acc5...&timestamp=1794925754514
User-Agent: Java/21.0.13
```

Further results:

- When the listener answers `302 Location: http://l05-listener2:8080/any/path`, the server follows it and listener2 receives `GET /any/path` (RestTemplate).
- Pointing the Host at another internal service works too.
- One login with the forged Host followed by 32 normal logins triggers the request with no signout at all.

Controls:

- Setting `curr-sso-logout-call` on the client makes the forged Host ignored.
- A proxy that forces `Host` also prevents it.

## Impact

A low-privileged SSO user can make the SSO server send GET requests to internal hosts and ports of their choice, and with RestTemplate to any path through a redirect. It is blind: signout always returns success and nothing from the target comes back. The request carries only the attacker's own loginId and a signed parameter set.

The docs' own nginx recipe in `fun/curr-domain.md` forwards `$http_host`, so it does not protect against this.

Suggested fix: validate the registered `ssoLogoutCall` against the client's allow-url on the server, as is already done for the login redirect. On the client, do not derive it from the request: require `curr-sso-logout-call` or `curr-domain` when `reg-logout-call` is on. Disabling redirect following for the notify request would also help.

## Affected versions

- Tested and affected: 1.46.0 (`ae58d1cc`), package `cn.dev33:sa-token-sso`, with the SSO server using the RestTemplate HTTP plugin (`sa-token-rest-template`).
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 1.46.0.

## Severity

CVSS 3.1 base score **5.0** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N`

- **AV:N** Plain HTTP.
- **AC:L** The documented anonymous-client config accepts any Host, directly or behind the nginx recipe in the docs. If a Host-trusting client deployment is treated as outside the attacker's control, AC:H gives 3.5.
- **PR:L** Any SSO account is enough.
- **UI:N** No victim action.
- **S:C** The requests leave from the SSO server's network position toward other internal services.
- **C:L** Blind; it shows internal reachability only.
- **I:N** No integrity effect shown.
- **A:N** No availability effect.

## Credit

thientc (VinSOC)
