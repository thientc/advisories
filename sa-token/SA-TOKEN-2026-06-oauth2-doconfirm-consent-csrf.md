# SA-TOKEN-2026-06: /oauth2/doConfirm has no CSRF protection, letting a registered client skip the consent screen

- Product: dromara/Sa-Token (https://github.com/dromara/Sa-Token)
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`/oauth2/doConfirm` records the user's consent after checking only that the user is logged in and that the method is POST. There is no confirm token and no Origin check. A third-party app registered on the server can post this form from its own page, in the victim's browser. The next `/oauth2/authorize` then skips the consent view and sends the app an authorization code for the victim.

## Details

v1.46.0 (`ae58d1cc`), `sa-token-plugin/sa-token-oauth2/src/main/java/cn/dev33/satoken/oauth2/`:

- `processor/SaOAuth2ServerProcessor.java:241-263` checks login, POST, client, contract scope, response type and redirect URI. Then `:269` calls `saveGrantScope(clientId, loginId, scopes)`.
- `state` is only checked for reuse, and here the attacker is the client and picks it.
- On the next authorize, `SaOAuth2Template.isNeedCarefulConfirm` (`:311`) returns false, and `SaOAuth2ServerProcessor.java:153-156` redirects the code to the client's URI.
- The Sa-Token cookie has no SameSite attribute by default (`SaCookieConfig.java:60`).

The confirm page examples in `oauth2-server.md`, `oauth2-scope-level.md` and the demo's `confirm.html` all POST to `doConfirm` without any token. So a host following the docs has no protection. I know `common-questions.md` leaves CSRF to the developer in general, but this endpoint ships with the library.

## PoC

Local lab only: Spring Boot 3.5.16, sa-token-oauth2 1.46.0 built from the tag, stock `dister()`, and a test user. Client 1001 stands for the attacker's app: `authorization_code`, `contractScopes [userinfo]`, redirect `http://evil07.lab:19011/cb`, `isAutoConfirm=false`.

Before anything else, the authorize request shows the confirm view. Then a page on `evil07.lab` auto-submits:

```
POST http://oauth07.lab:19010/oauth2/doConfirm
client_id=1001&response_type=code&redirect_uri=http://evil07.lab:19011/cb&scope=userinfo
-> 200 {"code":200,...}
GET /oauth2/authorize?response_type=code&client_id=1001&redirect_uri=http://evil07.lab:19011/cb&scope=userinfo&state=s2
-> 302 http://evil07.lab:19011/cb?code=...     (no confirm view)
```

The attacker exchanges the code with its own secret, and `/api/userinfo` with the token returns `login_id 20001`, the victim.

Whether the browser sends the cookie on the cross-site POST depended on the browser:

| Browser | Cookie sent on the cross-site POST |
|---|---|
| Playwright's Firefox 141 | Yes, in every mode, including a hidden iframe |
| Chromium 140 | Only within 2 minutes of login (Lax+POST), for a top-level or popup POST |
| Playwright's WebKit | No |

I did not test release Firefox or Safari.

## Impact

An app registered on the OAuth2 server gets a code, and then a token, for scopes the operator contracted to it. This happens without the user ever approving, for users who visit its page while logged in under the browser conditions above. Higher scopes always show the confirm view and are not affected. I rate it Low because it depends on the browser and needs a registered client.

Suggested fix: issue a one-time token with the confirm view and require it in `doConfirm`, or reject cross-site requests by `Origin` / `Sec-Fetch-Site`. Setting `SameSite=Lax` on the Sa-Token cookie by default would also close most of this.

## Affected versions

- Tested and affected: 1.46.0 (`ae58d1cc`), package `cn.dev33:sa-token-oauth2`, with a cookie session and the browser conditions above.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 1.46.0.

## Severity

CVSS 3.1 base score **3.7** (Low): `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N`

- **AV:N** Delivered as a web page.
- **AC:H** It depends on the browser: Chromium only sends the cookie in its 2-minute Lax+POST window, and Firefox was shown on the Playwright build only.
- **PR:L** The attacker owns a registered OAuth2 client with the general scope contracted.
- **UI:R** The victim visits the attacker's page while logged in.
- **S:U** The effect stays on the OAuth2 server and its resources.
- **C:L** Contracted general-scope data is released (in the lab, user info).
- **I:L** Consent is recorded without the user's approval.
- **A:N** No availability effect.

## Credit

thientc (VinSOC)
