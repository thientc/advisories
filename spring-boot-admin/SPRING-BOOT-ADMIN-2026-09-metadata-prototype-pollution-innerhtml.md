# SPRING-BOOT-ADMIN-2026-09: Registration metadata key `__proto__.innerHTML` pollutes Object.prototype and runs script on the admin origin

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin), version 4.1.5
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-18 through GitHub private vulnerability reporting, [GHSA-596f-gp3x-hp45](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-596f-gp3x-hp45); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-23, pending

## Summary

The UI turns an instance's registration metadata into a nested object with a dotted-key helper that does not guard `__proto__`. A registrant who sets the metadata key `__proto__.innerHTML` to an HTML string sets `Object.prototype.innerHTML` in the operator's tab. Vue then applies that inherited property to every element it mounts, so an `<img onerror>` value runs script on the Spring Boot Admin origin as soon as the operator opens any page of that instance, with no click.

## Details

`POST /instances` stores the `metadata` map unchanged, including a key `__proto__.innerHTML` (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:83`).

In the UI, `metadataParsed` calls `transformToJSON(metadata, 'LAX')` (`spring-boot-admin-server-ui/src/main/frontend/services/instance.ts:82-84`). The sidebar's `customLinksFromMetadata` reads it (`views/instances/shell/sidebar.vue:205`), and the sidebar renders before the instance view (`InstanceShell.vue:21-32`), so this runs on every `/instances/<id>/*` page.

`transformToJSON` splits the key on `.` and walks down the object (`utils/transformToJSON.ts:80`, `:117-122`). For the segment `__proto__`, `current[part]` is `Object.prototype`, which is truthy, so `current` becomes `Object.prototype` and the last segment is assigned there (`transformToJSON.ts:103`):

```
Object.prototype.innerHTML = <value>
```

There is no check for `__proto__`, `constructor` or `prototype`. In the shipped Vue 3.5 runtime, `mountElement` iterates element props with `for...in`, which includes inherited keys, and `patchProp` sets `innerHTML` as a DOM property. Each element mounted afterwards gets `el.innerHTML = <value>`, and an `<img src=data:, onerror=...>` value fires without interaction. The value never goes through `sanitizeHtml`; Vue writes the property itself.

An earlier probe with `__proto__.*` only crashed the page: that key is not a DOM property, so Vue called `setAttribute('*')` and threw. `innerHTML` is applied as a property and runs. SBA sets no CSP.

## PoC

Setup: Spring Boot Admin 4.1.5 with the UI, SSRF protection on (the stand-in's address range allowed), Chromium 140 (Playwright 1.55) logged in through the normal login form, with all requests except the Spring Boot Admin origin aborted. One authenticated USER account registered the instance and viewed it.

```
POST /instances
{"name":"l03b-protoinnerHTML","managementUrl":".../actuator","healthUrl":".../actuator/health","serviceUrl":".../",
 "metadata":{"__proto__.innerHTML":"<img src=data:, onerror=\"if(!window.__l03){window.__l03=1;document.title='<MARKER>';document.documentElement.dataset.sbabr='<MARKER>'}\">"}}
browser: open /instances/f3b4b8567aee/details   (no click)
```

The control used the same value under the key `l03.innerHTML`, an ordinary nested key.

| Probe | Metadata key | `String(({}).innerHTML)` in the page | Title | `<html data-sbabr>` |
|---|---|---|---|---|
| control | `l03.innerHTML` | `undefined` | `Spring Boot Admin` | none |
| attack | `__proto__.innerHTML` | the payload string | changes to the marker | the marker |

Control and attack ran twice each on the first build; both attacks set the marker on origin `http://gateway:8080` (the lab host name for the server). I repeated one control/attack pair in each of two sweeps on a rebuild of the same source with Spring Boot 4.1.2 (Spring Framework 7.0.10) with the same outcome.

After the attack the instance views do not render (only the navbar remains, console `TypeError ... reading 'insertBefore'`), because every newly mounted element has its content replaced. The pollution also stayed in the tab after an in-app route change to the same instance, and the view still failed to render; navigation to a different instance was not tested.

## Impact

A principal that can register an instance runs script on the admin origin in the browser of every operator who opens that instance, with no interaction, and leaves that tab's UI broken until reload. Only marker writes were made through this path. In the same lab, script on the origin delivered through the sidebar-label bug (SPRING-BOOT-ADMIN-2026-04) read the `XSRF-TOKEN` cookie and another instance's synthetic `/actuator/env` through the proxy, which shows what such script can reach; I did not repeat that read through this path.

This sink is independent of the sidebar-label one: escaping the label does not stop it, because no `sidebar.links` key is needed and no sanitizer is involved. The lab used one account to register and view. In the secured sample every authenticated user has full access (`spring-boot-admin-samples/.../SecuritySecureConfig.java:77-78`) and clients register as that same user (`application-secure.yml:3-10`), so a gain across privilege levels needs metadata from a discovery source or a registration-only credential set up by the deployment. I tested neither. Other keys (`constructor.prototype.<key>`) reach the same assignment by reading the code; I did not run them. Only Chromium 140 was tested.

Suggested fix: in `transformToJSON`, skip the keys `__proto__`, `constructor` and `prototype`, or build each level with `Object.create(null)` and assign with `Object.defineProperty`. A regression test: `transformToJSON({'__proto__.innerHTML': 'x'}, 'LAX')` should leave `({}).innerHTML` undefined. I did not apply or test this.

## Affected versions

- Tested and affected: 4.1.5 (source tag commit `c3034e1`, latest release when tested), run in a lab app on Spring Boot 4.1.2 for the repeat runs. Earlier versions were not tested.
- Fixed in: no fixed release known.

Tested on a local lab with synthetic accounts and data only; no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **4.1** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N`

- **AV:N** Registration and the UI are served over HTTP.
- **AC:L** Nothing beyond the preconditions once the instance is registered.
- **PR:L** The lab registration needed an authenticated USER. A Spring Boot Admin with no security (PR:N) was not run.
- **UI:R** An operator has to open a page of the instance; no click is needed.
- **S:C** Instance-supplied script runs on the admin origin with the operator's session.
- **C:L** Script on that origin can read operator-visible data (shown through the sidebar-label bug); only marker writes were made here.
- **I:N** No state change was demonstrated.
- **A:N** The tab's UI breaks until reload; I did not score it.

## Credit

thientc (VinSOC)
