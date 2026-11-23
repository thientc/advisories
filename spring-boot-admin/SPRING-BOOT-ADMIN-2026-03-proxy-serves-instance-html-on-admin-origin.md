# SPRING-BOOT-ADMIN-2026-03: Instance proxy serves a registered instance's `text/html` from the admin origin

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-04 through GitHub private vulnerability reporting, [GHSA-jm84-8c7p-cfrc](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-jm84-8c7p-cfrc) (filed against 4.1.4; still present in 4.1.5); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-23, pending
- Version: 4.1.5

## Summary

`/instances/{id}/actuator/**` proxies the instance's response back on the Spring Boot Admin origin and keeps the instance's `Content-Type`. A registered instance that answers its `logfile` endpoint as `text/html` makes SBA serve that HTML as a document, scripts included. In my lab a logged-in operator who opened the proxied logfile through the UI's Download button ran the instance's script on the SBA origin, and the script read `GET /instances` with the operator's session.

## Details

The proxy entry is `/instances/{instanceId}/actuator/**` (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/servlet/InstancesProxyController.java:86-88`). It copies the instance response headers through `HttpHeaderFilter.filterHeaders` (lines 108-110). That filter removes only hop-by-hop headers, the configured ignored headers (default `Cookie`, `Set-Cookie`, `Authorization`, `AdminServerProperties.java:263`) and headers named in `Connection` (`.../web/HttpHeaderFilter.java:39-41,51-59`), so `Content-Type` passes. Lines 114-116 stream the body under that type and add no `X-Content-Type-Options`, CSP or `Content-Disposition`.

The proxy path is a plain GET URL on the SBA origin that an operator's browser can navigate to, for example from the logfile view's Download button (`spring-boot-admin-server-ui/src/main/frontend/views/instances/logfile/index.vue:127`, `downloadLogfile()` at `:822-823`, which calls `window.open('instances/<id>/actuator/logfile', '_blank')`). The 4.1.5 change to `HttpHeaderFilter` (line 53) does not touch `Content-Type`.

## PoC

Lab: SBA 4.1.5 with the UI module, Spring Security form login, SSRF protection on with the mock's range allowed, and a mock instance that serves an actuator index with `logfile` and returns either `text/plain` (control) or `text/html` (attack) for it. The attack body is:

```html
<html><body><h1 id="l06"><M></h1><script>document.title='<M>'</script></body></html>
```

Register the instance with `POST /instances`, wait for `logfile` to be detected, then request the proxied logfile the way a browser navigation does:

```
GET /instances/<id>/actuator/logfile   (Accept: text/html,*/*)
-> 200
Content-Type: text/html
(no X-Content-Type-Options, no Content-Security-Policy, no Content-Disposition)
```

In four runs (text/plain control, text/html twice, text/plain control) the proxied type was always the instance's own, with no nosniff or CSP header.

Browser run, Chromium 140 logged in as an operator: open `/instances/<id>/logfile` and click Download. The mock's HTML here also made a same-origin `GET /instances` and wrote the result onto the page.

| Probe | New tab content type | Result |
|---|---|---|
| control (text/plain) | text/plain | markup shown as text, no script element |
| attack (text/html) | text/html on the SBA origin | title set to the marker; same-origin `GET /instances` returned 200 |

Both pairs behaved the same, and again in two sweeps after rebuilding the lab with Spring Boot 4.1.2. One caveat: the instance section's invisible loading overlay (`views/instances/shell/sba-instance-section.vue:27-31`) intercepted pointer clicks in the lab, so I dispatched the click on the Download button element, which runs the button's own handler. I did not settle why the view stayed in its loading state.

## Impact

A principal that can register an instance, or that controls a monitored app, can make the SBA origin serve an HTML page of its choosing. A logged-in operator who opens that proxy URL runs the page's script on the SBA origin with their session. In the browser run the script's `GET /instances` returned 200, and the list held only the attacker's own instance because no other was registered. Script on the SBA origin delivered a different way read other instances' synthetic actuator data through the proxy (see SPRING-BOOT-ADMIN-2026-04); I did not repeat that through this path. A CSP, `nosniff` or a download disposition added in front of SBA would change the effect.

Suggested fix: in the proxy, pass through only passive types (JSON, `+json`, `text/plain`, event-stream, CSV, NDJSON, octet-stream), map any other `Content-Type` to `application/octet-stream`, and always add `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`. I tested a patch like this in the lab against the servlet and reactive controllers and their tests passed.

## Affected versions

- Tested and affected: 4.1.5 (tag `4.1.5`, commit `c3034e1038afda381282fc7a9170a933a71a3e67`).
- The application proxy (`/applications/{name}/actuator/**`) and the reactive controller use the same filter; I did not run them separately.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **4.1** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N`

- **AV:N** Registration and the proxy path are plain HTTP endpoints.
- **AC:L** No condition beyond the stated preconditions once registered; SSRF protection is opt-in.
- **PR:L** Registration needed an authenticated user in the lab. An unsecured SBA (PR:N) was not run.
- **UI:R** A logged-in operator has to open the proxy URL; the logfile view's Download button does.
- **S:C** Content supplied by the instance executes on the SBA origin with the operator's session. With S:U the score would be 3.5.
- **C:L** The script read `/instances` with the operator's session; reading other instances' data was not shown through this path.
- **I:N** No state-changing request demonstrated.
- **A:N** None demonstrated.

## Credit

thientc (VinSOC)
