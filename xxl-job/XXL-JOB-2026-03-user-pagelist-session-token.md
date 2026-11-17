# XXL-JOB-2026-03: Admin user list returns other users' session tokens

| | |
|---|---|
| Product | XXL-JOB, `xxl-job-admin` (https://github.com/xuxueli/xxl-job) |
| Vendor | xuxueli |
| Affected version | 3.5.0 (latest release, tag commit `3bebfc16`). Earlier versions not tested. |
| Fixed version | none at time of writing |
| Vulnerability type | Information Disclosure (CWE-200) |
| Required access | Administrator |
| Severity | Low |
| CVE | pending |
| Reporter | thientc (VinSOC) |
| Related | CVE-2020-23811 |

## Summary

`POST /user/pageList` returns each user's current session token to administrators. The handler clears `password` before returning the list but leaves `token`, the signature in that user's login cookie.

## Details

`xxl-job-admin/src/main/java/com/xxl/job/admin/framework/controller/JobUserController.java:67`:

```java
for (XxlJobUser item: list) {
    item.setPassword(null);
}
```

The `token` field is returned unchanged. The login cookie is the user id plus this signature, so an administrator who reads the list has what is needed to build another user's cookie. CVE-2020-23811 covered the password in this same response; the token was not included in that fix.

## Proof of concept

Local 3.5.0 lab (Spring Boot 4.1.2) with test accounts. While test user `alice` was logged in:

```
POST /user/pageList   (admin's session)
username=&role=-1

{"code":200,"data":{"data":[{"id":1,...,"username":"admin"},
 {"id":2,"password":null,"permission":"2","role":0,"token":"<32 hex>","username":"alice"}],...}}
```

The returned token matched the signature in alice's login cookie. The same request from alice is refused (`does not have role:ADMIN`). I did not go on to log in with a rebuilt cookie.

## Impact

An administrator can impersonate other users, including other administrators, so actions are recorded under someone else's name. Only administrators can read the list, which keeps the severity low.

## Fix

Clear `token` along with `password`, or return a DTO without either.

## Timeline

- 2026-11-02: reported to the vendor by email. No reply.
- 2026-11-17: CVE requested from MITRE.
