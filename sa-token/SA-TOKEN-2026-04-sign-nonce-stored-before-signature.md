# SA-TOKEN-2026-04: sa-token-sign stores the nonce before checking the signature, allowing unauthenticated memory exhaustion

- Product: dromara/Sa-Token (https://github.com/dromara/Sa-Token)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-17 through GitHub private vulnerability reporting, [GHSA-445w-cfq4-vjj2](https://github.com/dromara/Sa-Token/security/advisories/GHSA-445w-cfq4-vjj2); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`SaSignTemplate.checkParamMap` stores the request's `nonce` in the token dao before it verifies `sign`. A request with a wrong signature is rejected, but its nonce stays in memory for about 30 minutes. Nothing limits the nonce's length. An unauthenticated client that sends large nonces with a bad signature can run the JVM out of heap through any `@SaCheckSign` endpoint.

## Details

All paths are in `sa-token-plugin/sa-token-sign/src/main/java/cn/dev33/satoken/sign/template/SaSignTemplate.java` (v1.46.0, `ae58d1cc`).

Lines 345-347 run three checks in this order:

```java
checkTimestamp(Long.parseLong(timestampValue));
checkNonce(nonceValue);
checkSign(paramMap, signValue);
```

`checkNonce` (`:267-281`) only checks that the nonce is not empty and not already used. It then calls `SaManager.getSaTokenDao().set(key, nonce, getSaveNonceExpire() * 2 + 2)` (`:280`):

- The key is `tokenName + ":sign:nonce:" + nonce` (`:413`), so the value is stored twice.
- The TTL is 1802 s with the default 15-minute window.

The default dao is the in-memory `SaTimedCache` (a plain `ConcurrentHashMap`, no size limit).

The plugin docs describe the opposite order. `api-sign.md` says the nonce is written to the cache after the signature check succeeds.

## PoC

Local lab only: Spring Boot 3.5.16 with `sa-token-spring-boot3-starter` and `sa-token-sign` 1.46.0 built from the tag, `sa-token.sign.secret-key` set, and `new SaInterceptor()` on `/**`. The endpoint is `@SaCheckSign @PostMapping("/api/sync")`. The JVM has `-Xmx384m`.

```
POST /api/sync   timestamp=<now>&nonce=probe1&sign=bad   -> 12202 无效签名：bad
POST /api/sync   timestamp=<now>&nonce=probe1&sign=bad   -> -1 此 nonce 已被使用过，不可重复使用：probe1
```

The second response shows the nonce from a rejected request was kept.

I then sent the same request with a random 1.9 MB nonce and `sign=bad` in a loop. 1.9 MB is under Spring Boot's default 2 MB form limit.

| Requests | Heap used after a full GC |
|---|---|
| 0 | 13.7 MB |
| 40 | 163 MB |
| 90 | 349 MB |

At request 97 the server logged `java.lang.OutOfMemoryError: Java heap space` and stopped responding.

As a control, I sent 200 requests with the same 1.9 MB of data in an ignored parameter and a short nonce. The heap stayed flat at about 15 MB. A request with a stale timestamp is rejected before the nonce is stored, so that check works. Memory came back after the 1802 s TTL.

## Impact

No secret or account is needed. Each request keeps about twice its nonce size in the heap for 30 minutes, so sending roughly half the heap within that window takes the application down. Resending keeps it down. With a Redis dao the same data goes into Redis; I did not test that, nor the SSO `/sso/pushS`, `/sso/pushC` and `/sso/logoutCall` routes, which call the same check. Common proxy body limits may raise the traffic needed.

Suggested fix: verify the signature first and store the nonce only after it passes, as the docs describe. A length limit on `nonce` (for example 64 characters) would also help.

## Affected versions

- Tested and affected: 1.46.0 (`ae58d1cc`), package `cn.dev33:sa-token-sign`, default in-memory dao.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 1.46.0.

## Severity

CVSS 3.1 base score **7.5** (High): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

- **AV:N** Plain HTTP.
- **AC:L** A fresh timestamp is trivial to produce and the endpoint is a stock `@SaCheckSign` one.
- **PR:N** The nonce is stored before the signature is verified, so no credential is needed.
- **UI:N** No victim action.
- **S:U** The effect stays inside the host JVM.
- **C:N** Nothing is disclosed.
- **I:N** Nothing is modified.
- **A:H** The JVM heap is exhausted and the attacker can keep it down by resending every 30 minutes. If a reviewer weighs the traffic needed (about half the heap per 30 minutes) and proxy body limits, A:L gives 5.3.

## Credit

thientc (VinSOC)
