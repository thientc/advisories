# SA-TOKEN-2026-01: Percent-encoded letters in the path bypass SaRouter rules in the Spring Boot 2 starter

- Product: dromara/Sa-Token (https://github.com/dromara/Sa-Token)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-17 through GitHub private vulnerability reporting, [GHSA-vg7p-x828-qvmx](https://github.com/dromara/Sa-Token/security/advisories/GHSA-vg7p-x828-qvmx); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

On the Spring Boot 2 starter, SaRouter rules are matched against the raw, still-encoded request URI, while Spring MVC decodes the path before it picks the handler. So `GET /%61dmin/secret` does not match `SaRouter.match("/admin/**", ...)`, but it is served by the `/admin/secret` handler. A logged-in user without the `admin` permission reads the admin response.

The firewall hooks do not block `%61`, because `bannedPercentage` is false by default. This is the same class of problem as issue #515 / CVE-2023-44794, where `/admin/..` was fixed in 1.37.0. Encoded ordinary letters were not covered by that fix.

## Details

v1.46.0 (`ae58d1cc`):

- `SaRequestForServlet.getRequestPath()` returns `request.getRequestURI()`, which is undecoded (`sa-token-starter/sa-token-servlet/.../SaRequestForServlet.java:153`).
- The Boot 2 starter installs `SaPatternsRequestConditionHolder` as the route matcher (`sa-token-starter/sa-token-spring-boot-starter/.../SaTokenContextRegister.java:46`). It runs Spring's `AntPathMatcher` on that raw string (`SaPatternsRequestConditionHolder.java:57`).
- `SaFirewallCheckHookForPathDangerCharacter` blocks `%2e`, `%2f`, `%5c`, `%25`, `;` and similar, but not `%61`, `%69` or `%73` (`:42-57`, `:76`).

The Boot 3 and Boot 4 starters use `PathPattern` on a decoded `PathContainer`. I confirmed in the lab that they are not affected.

## PoC

Local lab: Spring Boot 2.7.18 (Spring MVC 5.3.31, Tomcat 9.0.83) with sa-token-spring-boot-starter 1.46.0 built from the tag, and test accounts. The rules are the ones from issue #515:

```java
SaRouter.match("/**").notMatch("/user/doLogin").check(r -> StpUtil.checkLogin());
SaRouter.match("/admin/**", r -> StpUtil.checkPermission("admin"));
```

User 10001 has only the `user` permission. `/admin/secret` returns a marker string.

```
user GET /admin/secret        -> 403 NotPermissionException: 无此权限：admin
user GET /%61dmin/secret      -> 200 SATOKEN-ADMIN-MARKER-4s88ofZH
user GET /adm%69n/secret      -> 200 SATOKEN-ADMIN-MARKER-4s88ofZH
user GET /%61dmin/%73ecret    -> 200 SATOKEN-ADMIN-MARKER-4s88ofZH
```

(curl needs `--path-as-is`.)

When `SaRouter.match("/admin/**", r -> StpUtil.checkLogin())` is the only rule, the same paths return the marker with no token at all. The same app on Boot 3.5.16 with `sa-token-spring-boot3-starter` returns 403 for every encoded variant.

## Impact

Path-based rules on the Boot 2 starter can be skipped by encoding one letter of the protected prefix. With the documented `/**` login rule, any logged-in user reaches handlers meant for a higher permission. If the prefix rule is the only guard, no login is needed (PR:N, 7.5). Annotation checks such as `@SaCheckPermission` on the handler itself are not affected. I only demonstrated reads; if the bypassed handler writes, integrity is affected as well.

Suggested fix: match rules against the decoded, normalised lookup path in the Boot 2 starter, for example `UrlPathHelper.getLookupPathForRequest`. Alternatively, have the firewall reject percent-escapes that decode to unreserved characters.

## Affected versions

- Tested and affected: 1.46.0 (`ae58d1cc`), package `cn.dev33:sa-token-spring-boot-starter` on Spring Boot 2.7.18.
- Not affected in my lab: the Boot 3 starter on Spring Boot 3.5.16.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 1.46.0.

## Severity

CVSS 3.1 base score **6.5** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

- **AV:N** A single HTTP request.
- **AC:L** The documented SaRouter rules on the Boot 2 starter are the vulnerable setup; no extra condition is needed.
- **PR:L** The documented `/**` checkLogin rule still applies to the encoded path, so a low-privilege login is needed. When the prefix rule is the only guard it is PR:N (7.5).
- **UI:N** No victim action.
- **S:U** The effect stays inside the host application.
- **C:H** The response of an admin-only handler is returned to a non-admin user.
- **I:N** Only reads were demonstrated (I:H if the bypassed handler writes).
- **A:N** No availability effect.

## Credit

thientc (VinSOC)
