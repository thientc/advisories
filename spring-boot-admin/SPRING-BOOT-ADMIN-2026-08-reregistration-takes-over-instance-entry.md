# SPRING-BOOT-ADMIN-2026-08: Re-registering an instance's health URL takes over its entry and leaks its actuator credentials to the registrant

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin), version 4.1.5
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-18 through GitHub private vulnerability reporting, [GHSA-h3gm-vqjp-jmm5](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-h3gm-vqjp-jmm5); in triage, no maintainer reply as of 2026-11-23; follow-up comment posted 2026-11-23
- CVE: requested from MITRE on 2026-11-23, pending

## Summary

An instance id in Spring Boot Admin is derived from the health URL alone. Any principal that can call `POST /instances` can re-register a monitored app's exact health URL with a different `managementUrl` and replace that app's entry. When the real client then re-registers itself, the server sends the app's own actuator credentials (from its registration metadata) to the attacker's endpoint. In my lab the credential reached the attacker in 25 of 25 attempts with a simulated heartbeat and 12 of 12 with a real `spring-boot-admin-client`.

## Details

`POST /instances` binds the registrant's `Registration` and overwrites only `source` (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:82-85`). The instance id is the first 12 hex digits of SHA-1 of the health URL, nothing else (`services/HashingInstanceUrlIdGenerator.java:35-39`).

After the SSRF URL checks, the registry calls `repository.compute(id, ... instance.register(registration))` on the existing instance, with no comparison of principal or source (`services/InstanceRegistry.java:64-76`). A differing registration replaces name, `managementUrl`, `serviceUrl` and metadata, while status, info and the detected endpoints are kept (`domain/entities/Instance.java:119-130`, `:216-221`). The update event then re-detects endpoints against the attacker's `managementUrl` (`services/EndpointDetectionTrigger.java:44-46`), so proxied operator calls resolve to the attacker's endpoints (`web/client/InstanceExchangeFilterFunctions.java:105-109`).

The leak comes from the order of events. When the real client re-registers, restoring its own metadata, the update event also triggers an info fetch (`services/InfoUpdateTrigger.java:64-67`, `services/InfoUpdater.java:66-82`). That fetch runs on the instance as it is at that moment: the client's restored credential metadata, but the attacker's still-stored `info` endpoint. `BasicAuthHttpHeaderProvider` builds `Authorization: Basic` from the restored `user.name` and `user.password` and sends it to the attacker's info URL (`web/client/BasicAuthHttpHeaderProvider.java:81-100`).

One reason this could be safe is that re-registration is how a client updates itself and it restores its own entry on the next heartbeat (every 10 s by default, `ClientProperties.java:46` in `spring-boot-admin-client`). That is what causes the leak: each restore fires the update event. Another is the SSRF filter. It limits where the attacker can listen, not who receives the credential.

## PoC

Setup: Spring Boot Admin 4.1.5 with SSRF protection on (the stand-in's address range allowed), a stand-in host serving `/legit/actuator` and `/atk/actuator` trees and logging method, path and `Authorization` of every request, and one authenticated USER account. The "legitimate" registration carries synthetic credentials as metadata (`user.name=legit-synth`, `user.password=<synthetic>`).

```
legit:    POST /instances {"name":"legit-app","healthUrl":".../legit/actuator/health",
           "managementUrl":".../legit/actuator","serviceUrl":".../legit/",
           "metadata":{"user.name":"legit-synth","user.password":"<synthetic>","owner":"legit"}}   -> id bfa2fa5e8398
attacker: POST /instances {"name":"atk-app","healthUrl":".../legit/actuator/health",
           "managementUrl":".../atk/actuator","serviceUrl":".../atk/",
           "metadata":{"owner":"attacker"}}                                                        -> id bfa2fa5e8398 (same)
```

Overwrite and redirect: `GET /instances/bfa2fa5e8398` then showed name `atk-app`, `managementUrl` on `/atk/actuator` and the attacker's metadata, with status still UP. Endpoints were re-detected within 0.09 s. The operator's `GET .../actuator/info` returned the attacker's tree, and a `POST .../actuator/env` with the XSRF token returned 200 from the attacker; the stand-in logged it at `/atk/actuator/env` and nothing reached `/legit/`.

Credential leak, after the legitimate registration is re-posted (what the client's heartbeat does):

```
dt 0.095  GET /legit/actuator         Authorization: Basic <base64 legit-synth:...>
dt 0.096  GET /legit/actuator/health  Authorization: Basic <same>
dt 0.099  GET /atk/actuator/info      Authorization: Basic <same>      <- attacker receives the credential
dt 0.103  GET /legit/actuator/info    Authorization: Basic <same>
```

| Set | Runs | Credential received at the attacker's tree |
|---|---|---|
| attack, simulated heartbeat | 25 | 25 / 25 (0.088 to 0.117 s after the re-post) |
| control: attacker uses a different health URL | 25 | 0 / 25 |
| control: legitimate re-post, no attacker | 25 | 0 / 25 |

I also ran a real `spring-boot-admin-client` built from the pinned source (Spring Boot 4.1.2), registering every 10 s with `user.name` and `user.password` metadata and an actuator that required exactly that Basic credential. The attacker posted the client's exact health URL with a `managementUrl` on the stand-in's attacker tree, then did nothing. In 12 of 12 runs the attacker's tree received `GET /atk/actuator/info` with the client's credential, 0.006 to 0.118 s after the client's own re-registration; the two controls (different health URL, and no attacker) gave 0 of 12 each. While the attacker's registration was in place the entry showed DOWN, because the server probed the client without the credential and the client refused it. I repeated the simulated-heartbeat attack and both controls twice more on a rebuild of the same source with Spring Boot 4.1.2 (3 of 3 each time, controls 0 of 3).

With the attacker re-posting every second against the legitimate re-post every 10 s for 60 seconds, the attacker's registration was visible in 94 of 102 samples, and six `GET /atk/actuator/info` requests carried the credential, one per legitimate re-post after the first.

## Impact

A principal that can register an instance and knows a monitored app's health URL (listed by `GET /instances`) can take over that app's entry. Operator actions on the entry go to the attacker, and every time the real app re-registers, the app's actuator credential is sent to the attacker with no operator action.

The server masks the stored password (`user.password: "******"` in `GET /instances`), and the leaked raw credential is reusable directly against the app. In a deployment where every Spring Boot Admin user is trusted with full access, that user could already drive the app's actuator through the proxy; the added capability is the raw credential. I did not try the leaked credential against the real app. The lab used one account for both registrants, and other client setups (discovery-based registration, other heartbeat periods) were not run.

Suggested fix: bind an instance id to the principal or source that first registered it and refuse or quarantine a re-registration from a different one. Separately, clear the stored endpoints and skip the info fetch when a registration update changes `managementUrl`, so a credential is never sent to endpoints detected for another registration. A regression test: register A with credential metadata, re-register A's health URL with a different `managementUrl`, re-register A; no request to the second `managementUrl` may carry A's credentials. I did not apply or test this.

## Affected versions

- Tested and affected: 4.1.5 (source tag commit `c3034e1`, latest release when tested), run in a lab app on Spring Boot 4.1.2 for the repeat runs. Earlier versions were not tested.
- Fixed in: no fixed release known.

Tested on a local lab with synthetic accounts and data only; no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **6.5** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

- **AV:N** Registration and the instance calls are plain HTTP.
- **AC:L** The health URL is listed by `GET /instances`, and the leak happened on every legitimate re-registration, so there is no timing race to win.
- **PR:L** The lab registration needed an authenticated USER. A Spring Boot Admin with no security (PR:N) was not run.
- **UI:N** The server sends the request on the client's heartbeat; no operator action.
- **S:U** The disclosure is of a credential the server holds for the monitored app; using it against the app was not tried.
- **C:H** The full user name and password for the app's actuator are disclosed (synthetic in the lab).
- **I:N** Operator actions redirected to the attacker (info, env set) were observed but I did not score them; no change to the real app was shown.
- **A:N** None demonstrated.

## Credit

thientc (VinSOC)
