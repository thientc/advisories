# SPRING-BOOT-ADMIN-2026-01: Instance-supplied SBOM license URL runs as `javascript:` on the admin origin

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-04 through GitHub private vulnerability reporting, [GHSA-6g8m-59r6-vh42](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-6g8m-59r6-vh42) (filed against 4.1.4; still present in 4.1.5); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-23, pending
- Version: 4.1.5

## Summary

The Dependencies view renders each license URL from an instance's `/actuator/sbom/{id}` response as `<a :href="licenseItem.url">` with no scheme check and no `target`. A monitored app that serves a `javascript:` license URL gets that script run on the Spring Boot Admin origin, with the operator's session, when the operator clicks the license link. In my lab the click replaced the page body with the script's result and the page stayed on the admin origin.

## Details

`POST /instances` registers a registrant-chosen `managementUrl` and SBA detects the `sbom` endpoint from its actuator index (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:83`). The UI then fetches `/instances/{id}/actuator/sbom/application` through the proxy, which returns the CycloneDX body unchanged (`.../web/servlet/InstancesProxyController.java:86-116`).

In `spring-boot-admin-server-ui/src/main/frontend/views/instances/dependencies/SbomList.vue`, license items are filtered only for a present `license` object (lines 54-58). Line 60 binds the URL straight into the anchor:

```html
<a :href="licenseItem.url">
```

Vue escapes markup in the attribute value but not the URL scheme, so `javascript:` stays navigable. The anchor has no `target`, so the click navigates the SBA document itself. The registration-URL links in `ItemInformation.vue` are not affected because they open in a new tab with noopener. SBA sets no Content-Security-Policy on its responses, and I saw none in the lab.

## PoC

Lab: SBA 4.1.5 built from the tag, UI module included, Spring Security form login, SSRF protection on with the mock's address range allowed, and a mock monitored app that serves an actuator index with `sbom` and an SBOM with three components. The license URLs are `javascript:document.title='<M>'`, `javascript:void(document.title='<M>-VOID')` and, as a control, `https://license.example.invalid/LICENSE-2.0`.

```
POST /instances
{"name":"attack","managementUrl":"http://<mock>:8080/actuator",
 "healthUrl":"http://<mock>:8080/actuator/health","serviceUrl":"http://<mock>:8080/","metadata":{}}
```

Then, in Chromium logged in to SBA as a user, open `/instances/<id>/dependencies` and click each license link.

| Link clicked | Result |
|---|---|
| https control | navigation left the origin, nothing ran |
| `javascript:document.title=...` | body text became exactly `<M>`, origin still `http://<sba>:8080` |
| `javascript:void(document.title=...)` | page kept, title set to `<M>-VOID`, origin still `http://<sba>:8080` |

Each probe used a fresh registration, browser context and login, and the instance was deleted afterwards (DELETE 204, then GET 404). I ran it twice on the first build and twice more after rebuilding the lab with Spring Boot 4.1.2 as the app parent; the result was the same each time.

## Impact

The writer is the instance, not the viewer. The SBOM comes from the monitored app's own actuator, so a compromised or malicious monitored app, including one registered through discovery, reaches the operator. Registering the mock with the same account that viewed the page was a lab convenience.

Script chosen by the instance runs on the SBA origin with the logged-in operator's session after one click on a license link. In the same lab, script that ran on the SBA origin (delivered through the sidebar label in SPRING-BOOT-ADMIN-2026-04) read the `XSRF-TOKEN` cookie and another monitored instance's synthetic `/actuator/env` through the SBA proxy. I did not repeat that read through this link. No state-changing request was tried. A CSP or a reverse proxy in front of SBA could change the effect; I did not test one.

Suggested fix: allow only `http:` and `https:` license URLs before binding (parse with `new URL()`, render the name as plain text otherwise), and send a CSP that blocks `javascript:` navigation. I did not test this patch.

## Affected versions

- Tested and affected: 4.1.5 (tag `4.1.5`, commit `c3034e1038afda381282fc7a9170a933a71a3e67`).
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only, in one browser (Chromium 140); no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **4.1** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N`

- **AV:N** Registration, the proxy and the UI are plain HTTP endpoints.
- **AC:L** No condition beyond the stated preconditions once an instance is registered. SSRF protection is opt-in; the allowed range in my lab only made up for a non-public lab address.
- **PR:L** Registration needed an authenticated user in the lab. An unsecured SBA (PR:N) was not run.
- **UI:R** The operator has to open Dependencies and click the license link.
- **S:C** Script supplied through an instance runs on the SBA origin with the operator's session.
- **C:L** Script on the SBA origin read the CSRF cookie and another instance's synthetic `/actuator/env` through the proxy in the same lab.
- **I:N** No state-changing request was demonstrated.
- **A:N** None demonstrated.

## Credit

thientc (VinSOC)
