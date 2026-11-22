# MALL-2026-01: Unauthenticated login as any user via unsigned (alg:none) JWT

- Product: macrozheng/mall (https://github.com/macrozheng/mall)
- Reporter: thientc (VinSOC)
- Vendor status: no private reporting channel (GitHub private vulnerability reporting disabled, no SECURITY.md); vendor notified on 2026-11-18 via public GitHub issue https://github.com/macrozheng/mall/issues/1042 (contact request, no technical details), no reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`JwtTokenUtil` in `mall-security` accepts JWTs with `"alg":"none"` and an empty signature. Anyone who knows a username (the seeded `admin` super administrator, for example) can send an unsigned token and be authenticated as that user on mall-admin and mall-portal. No password and no knowledge of `jwt.secret` is needed. `/admin/refreshToken` and `/sso/refreshToken` will then turn the forged token into a normal HS256 token signed with the real secret.

## Details

`getPayloadFromToken` checks the signature with Hutool (5.8.40):

```java
// mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:62
if (!JWTUtil.verify(token, getSigningKey())) {
```

`JWTUtil.verify(token, byte[] key)` calls `JWT.setKey(key)`, which builds the signer from the algorithm named in the token's own header. For `"alg":"none"` Hutool returns its `NoneJWTSigner`, which accepts an empty signature, so the HMAC key is never used and the check passes for any unsigned token.

This part is a known Hutool bug: Hutool issue #4105 (https://github.com/chinabugotech/hutool/issues/4105, 2025-10-21), fixed in Hutool 5.8.42 (2025-11-28). There is no CVE or GHSA for it, so dependency scanners do not flag it. mall's root `pom.xml` (line 41) still pins `hutool.version` 5.8.40. I ran the same `JWTUtil.verify(token, key)` call against the jars from Maven Central: 5.8.40 and 5.8.41 accept the unsigned token, while 5.8.42 and 5.8.48 (the latest) throw `JWTException: When key is not null, algorithmId must not be none.` A correctly signed token is accepted by all four.

After that nothing else stops it:

- `JwtAuthenticationTokenFilter` (`mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40-51`) takes the `sub` claim, loads that user and calls `validateToken`.
- `validateToken` (`JwtTokenUtil.java:94-98`) only compares `sub` with the loaded username, checks expiry and `isEnabled()`.
- `isTokenExpired` (`JwtTokenUtil.java:111-114`) returns `false` when the token has no `exp` claim, so an unsigned token without `exp` never expires.
- The filter then puts the real user's authorities into the security context, so the forged session has exactly the privileges of the impersonated account.

`refreshHeadToken` (`JwtTokenUtil.java:154-177`) reads the payload through the same check and passes it to `generateToken`, which signs it with the configured secret and a fresh 7-day `exp`. The forged identity comes back as a genuinely signed token.

The bug came in with commit 0504e86, which moved `JwtTokenUtil` from jjwt to Hutool's `JWTUtil`. The v1.0.3 tag still uses jjwt (`parseClaimsJws`, which rejects unsigned tokens); I did not run it.

## PoC

Default config, the stock `mall.sql` seed, mall-admin on port 8080 and mall-portal on 8085. Build the token (the trailing dot is the empty signature):

```sh
ADMIN=http://<mall-admin-host>:8080
b64url() { printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=\n'; }
T="$(b64url '{"alg":"none","typ":"JWT"}').$(b64url '{"sub":"admin"}')."

# --oauth2-bearer sends the token as a standard Bearer header
curl -s "$ADMIN/admin/info"         --oauth2-bearer "$T"
curl -s "$ADMIN/admin/list"         --oauth2-bearer "$T"
curl -s "$ADMIN/admin/refreshToken" --oauth2-bearer "$T"
```
What I saw in my lab:

- Without a token, or with an HS512 token carrying a random signature, `/admin/list` returns `{"code":401,"message":"暂未登录或token已经过期"...}`.
- With the unsigned token, `/admin/info` returns `code 200` with the role `超级管理员` and the full menu tree, and `/admin/list` returns every admin row including the bcrypt password hashes. `/brand/list` and `/role/listAll` also return 200.
- A forged token for an admin that has no roles gets `{"code":403,"message":"没有相关权限"}` on the same URLs, which confirms the forgery carries the target account's own authorities.
- On mall-portal, `{"sub":"<member username>"}` sent to `/sso/info` returns that member's profile (phone number, password hash).
- `/admin/refreshToken` returns a token whose header is `{"typ":"JWT","alg":"HS256"}`. Its signature verifies with `mall-admin-secret`, and it works on `/admin/info`. The same happens on `/sso/refreshToken` with `mall-portal-secret`.
- An `alg:none` token whose `exp` is in the past is rejected, and an unknown `sub` is rejected.

## Impact

An unauthenticated attacker who knows or guesses one username can act as that user. The default install seeds `admin` with the super administrator role, so this gives full control of the admin API: I confirmed reads of all admin and member records; writes and deletes follow from the same role but I did not exercise them. Member accounts on the storefront can be taken over the same way. Changing `jwt.secret` does not help, because the secret is never consulted for these tokens, and the refresh endpoints let the attacker keep a properly signed session.

Suggested fix: verify with a fixed signer instead of the header-selected one, e.g. `JWT.of(token).setSigner(JWTSignerUtil.hs256(key)).verify()`, reject any token whose header `alg` is not the expected one, and treat a missing `exp` as invalid. I tested that change on a patched build: unsigned tokens, HS512 tokens and tokens without `exp` are refused, while normal login, `/admin/info`, `/sso/info` and refresh of a genuine token keep working.

At minimum, bump `hutool.version` to 5.8.42 or later. I checked that against the library, not in a rebuilt mall. On its own it still leaves tokens without `exp` valid forever, so the signer and `exp` changes above are still worth making.

## Affected versions

- Tested and affected: master at commit dcaa93b (`master-dcaa93b`).
- Introduced in commit 0504e86 (2026-05-14, Spring Boot 3.5 upgrade), which replaced jjwt with Hutool `JWTUtil`. No tagged release contains it; v1.0.3 (jjwt) is not affected.
- Root cause in the dependency: Hutool `cn.hutool:hutool-all` / `hutool-jwt` before 5.8.42 (Hutool issue #4105). mall master pins 5.8.40.
- Fixed in: no fixed mall release was known when this report was drafted. The Hutool side is fixed in 5.8.42.
- Other versions were not tested.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: master-dcaa93b.

## Severity

CVSS 3.1 base score **9.8** (Critical): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

- **AV:N** The admin and portal REST APIs are reached over HTTP.
- **AC:L** One unsigned token; no race and no secret, only a known username.
- **PR:N** No credentials at all.
- **UI:N** No victim interaction.
- **S:U** The attacker gets the impersonated user's rights inside the same application.
- **C:H** Reads of all admin records (with password hashes) and member records were observed.
- **I:H / A:H** The super administrator role covers every write, disable and delete endpoint of the admin API; these follow from the role and were not exercised.

## Credit

thientc (VinSOC)
