# SPRING-BOOT-ADMIN-2026-06: Instance name is formatted into the OpsGenie close-alert URL, so a registrant can close another instance's alert

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin), version 4.1.5
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-18 through GitHub private vulnerability reporting, [GHSA-rwv7-wfcr-g4v5](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-rwv7-wfcr-g4v5); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-23, pending

## Summary

When the OpsGenie notifier is enabled, Spring Boot Admin builds the "close alert" URL by formatting the instance's registered name into a string. A registrant who names its instance `<victim alias>/close?identifierType=alias#` makes the notifier send the close request for the victim's alias, with the operator's `GenieKey`, when the attacker's own instance goes from DOWN to UP. In my lab the victim's alert was closed while the victim was still DOWN.

## Details

`POST /instances` binds the registrant's `Registration`, including `name` (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:84`). The only check on the name is `Assert.hasText` (`domain/values/Registration.java:74`), so `/`, `?` and `#` are accepted.

A DOWN to UP change of the registrant's own instance passes `shouldNotify` (`notify/AbstractStatusChangeNotifier.java:57-65`; only `UNKNOWN:UP` is ignored by default). `OpsGenieNotifier` then derives the alias from the raw name plus the instance id (`notify/OpsGenieNotifier.java:159-161`) and builds the close URL on UP (`OpsGenieNotifier.java:112-117`):

```java
String.format("%s/%s/close?identifierType=alias", url, generateAlias(instance))
```

The string goes to `restTemplate.exchange(String, POST, ...)` (`OpsGenieNotifier.java:107-109`). That overload treats the string as a URI template, so `/`, `?` and `#` in the name are parsed as path, query and fragment before anything is encoded. A name of `<victim alias>/close?identifierType=alias#` produces:

```
<url>/<victim alias>/close?identifierType=alias#_<own id>/close?identifierType=alias
```

The fragment is not sent, so OpsGenie gets a close request for the victim alias. Every notification carries `Authorization: GenieKey <operator apiKey>` (`OpsGenieNotifier.java:155`). The victim alias is `<victim name>_<victim id>`. Both parts are listed by `GET /instances` to any user who can read Spring Boot Admin, and the id is the first 12 hex digits of SHA-1 of the health URL (`services/HashingInstanceUrlIdGenerator.java:35-39`).

One reason this might be safe is that the alias is a single path segment and the URI builder encodes it. It does not hold, for the reason above: the string overload parses the structure first. A second is that a registrant can only change the state of its own instance. That does not hold either, because the alias in the close request comes from the registrant's chosen name, not from the instance that changed.

## PoC

Setup: Spring Boot Admin 4.1.5 with the OpsGenie notifier enabled (`spring.boot.admin.notify.opsgenie.api-key` set to a synthetic key, `...opsgenie.url` pointed at a local stand-in that records requests and keeps an open or closed state per alias). SSRF protection was on, with the stand-in's address range allowed. The stand-in also served the monitored instances: the "victim" instance reported DOWN permanently, the attacker instance reported DOWN for 25 seconds after the first health poll and UP after that. One authenticated USER account made both registrations.

Control (attacker uses a plain name):

```
POST /instances  {"name":"payments-1","healthUrl":".../victim/.../actuator/health",...}   -> id 94bad12beb03
stand-in: POST /v2/alerts {alias "payments-1_94bad12beb03"}                               -> victim alert open
POST /instances  {"name":"atk-1","healthUrl":".../atk/.../actuator/health",...}          -> id dc1a27abec75
stand-in: POST /v2/alerts {alias "atk-1_dc1a27abec75"}  (DOWN)
stand-in: POST /v2/alerts/atk-1_dc1a27abec75/close?identifierType=alias  (UP)
-> victim alert stays open
```

Attack:

```
POST /instances  {"name":"payments-2","healthUrl":".../victim/.../actuator/health",...}   -> id 506e61de6eec
stand-in: POST /v2/alerts {alias "payments-2_506e61de6eec"}                               -> victim alert open
POST /instances  {"name":"payments-2_506e61de6eec/close?identifierType=alias#","healthUrl":".../atk/.../actuator/health",...}   -> id e3d345eb048a
stand-in: POST /v2/alerts {alias "payments-2_506e61de6eec/close?identifierType=alias#_e3d345eb048a"}   (attacker DOWN)
stand-in: POST /v2/alerts/payments-2_506e61de6eec/close?identifierType=alias   Authorization: GenieKey <synthetic key>   (attacker UP)
-> victim alert closed; GET /instances/506e61de6eec still reports status DOWN
```

I ran control, attack, control, attack in that order, resetting between runs (both instances deleted, 204 then 404). Both attacks closed the victim alert with the key attached, and both controls closed only the attacker's own alias. I repeated the whole sequence twice more on a rebuild of the same 4.1.5 source with Spring Boot 4.1.2 (Spring Framework 7.0.10): 2 of 2 attacks and 2 of 2 controls behaved the same in each sweep.

## Impact

A principal that can register an instance can close any other instance's OpsGenie alert, silencing paging for a service that is still down, using the operator's integration key and with no operator action. The key itself is not disclosed to the attacker.

I only tested the close action. The path before `/close` is attacker-chosen, so other OpsGenie API paths under the same key may be reachable; I did not try that. OpsGenie itself was not involved: the real API's handling of the injected path was not tested. Where the registrant is also a full Spring Boot Admin user, the cost to the attacker is low; the point is that the close targets another instance's alert.

Suggested fix: encode the alias as one path segment (`UriComponentsBuilder.fromUri(url).pathSegment(alias, "close").queryParam("identifierType", "alias")`, or pass the alias as a URI variable instead of formatting it into the template), and consider restricting instance names to a safe character set at registration. A regression test: an instance named `x/close?identifierType=alias#` should produce a request whose path is `/v2/alerts/x%2Fclose%3FidentifierType%3Dalias%23_<id>/close`. I did not apply or test this change.

## Affected versions

- Tested and affected: 4.1.5 (source tag commit `c3034e1`, latest release when tested), run in a lab app on Spring Boot 4.1.2. Earlier versions were not tested.
- Fixed in: no fixed release known.

Tested on a local lab with synthetic accounts and data only; no live deployment and no real OpsGenie account was used. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **5.0** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N`

- **AV:N** Registration is a network HTTP API.
- **AC:L** Once the notifier is enabled, the attacker needs the victim alias (listed by `GET /instances`) and control of its own instance's health.
- **PR:L** The lab registration needed an authenticated USER. A Spring Boot Admin with no security (PR:N) was not run.
- **UI:N** The server sends the close request on its own status change handling.
- **S:C** The changed state is in OpsGenie, a different component, and it is changed with the operator's integration key.
- **C:N** The key is not disclosed and nothing is read.
- **I:L** Another instance's open alert is closed while that instance is still DOWN (2 of 2 per sweep, against a local stand-in).
- **A:N** No availability effect was demonstrated.

## Credit

thientc (VinSOC)
