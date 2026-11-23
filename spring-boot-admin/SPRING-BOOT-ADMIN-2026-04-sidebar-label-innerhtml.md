# SPRING-BOOT-ADMIN-2026-04: Registration metadata sidebar label is rendered with `innerHTML`

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-18 through GitHub private vulnerability reporting, [GHSA-w69c-89vm-f3p2](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-w69c-89vm-f3p2); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-23, pending
- Version: 4.1.5

## Summary

An instance's `sidebar.links.N.label` metadata is assigned to `innerHTML` in the instance sidebar. Anyone who can register an instance with metadata can put an `<img onerror=...>` label there, and the script runs on the Spring Boot Admin origin in the browser of any operator who opens that instance. No click on the injected element is needed. In my lab the handler ran as soon as the instance's details page loaded.

## Details

`POST /instances` stores the registrant's `metadata` map as given (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:83`); the stored registration returned the label unchanged. In the UI, `metadataParsed` turns dotted keys into an object (`spring-boot-admin-server-ui/src/main/frontend/services/instance.ts:82-85`) and `customLinksFromMetadata` reads `sidebar.links` (`views/instances/shell/sidebar.vue:204-205`).

The sink is `views/instances/shell/sidebar.vue:208`:

```js
handle: () => h('span', { innerHTML: view.label })
```

For a link with a URL and no `iframe` flag, the span is rendered through `<component :is="view.handle" />` inside the `<a target="_blank">` branch (`sidebar.vue:152-162`) whenever the instance shell shows its sidebar. Only the link `title` goes through `stripHtml(view.label)` (line 209), and `stripHtml` (lines 297-301) parses the label with `innerHTML` on a detached `div`, so it is not a guard either (from source; I did not test it alone). The UI's `sanitizeHtml` is not called on this path, and SBA sets no CSP. The `target="_blank" rel="noopener"` on the link affects only the `href`, not the label.

## PoC

Lab: SBA 4.1.5 with the UI module, Spring Security form login, SSRF protection on with the mock's range allowed, a mock instance, and Chromium 140 logged in as a user.

Control:

```
POST /instances
{"name":"control","managementUrl":"http://<mock>:8080/actuator","healthUrl":"http://<mock>:8080/actuator/health",
 "serviceUrl":"http://<mock>:8080/",
 "metadata":{"sidebar.links.0.label":"docs","sidebar.links.0.url":"https://docs.example.invalid"}}
browser: /instances/<id>/details
-> title stays "Spring Boot Admin"; label rendered as <span>docs</span>
```

Attack:

```
POST /instances
{"name":"attack", ...same URLs...,
 "metadata":{"sidebar.links.0.label":"<img src=x onerror=\"document.title='<M>';document.documentElement.dataset.sbabr='<M>'\">",
             "sidebar.links.0.url":"https://docs.example.invalid"}}
browser: /instances/<id>/details
-> title history ["Spring Boot Admin", "<M>"]; <html data-sbabr="<M>">; origin http://<sba>:8080
```

I ran two attack and control pairs on the first build and two sweeps after rebuilding the lab with Spring Boot 4.1.2; each attack fired without a click, and the plain-label control ran nothing. Each instance was deleted afterwards (204, then 404).

## Impact

A principal that can register an instance runs script on the SBA origin in the browser of any operator who opens that instance. In SBA's documented secure setup the monitored apps register with a shared client credential, which may also open the UI, so the clear cross-principal cases are a discovery source or a monitored app that registers under a client account the operator does not use to browse. My lab used one account for registering and viewing, so it shows the mechanism, not the separation between two principals.

In one run, script delivered this way read the `XSRF-TOKEN` cookie (present, 36 characters; I did not store the value) and read another monitored instance's synthetic `/actuator/env` through the SBA proxy. Only GET requests were made; shutdown, restart and env set were not tried. A CSP in front of SBA would change the effect; I did not test one.

Suggested fix: render the label as text (`h('span', view.label)`), or pass it through the existing `sanitizeHtml` if HTML labels are a feature, and make `stripHtml` use `new DOMParser().parseFromString(html, 'text/html').body.textContent` so it runs no handlers. I did not test this patch.

## Affected versions

- Tested and affected: 4.1.5 (tag `4.1.5`, commit `c3034e1038afda381282fc7a9170a933a71a3e67`). The 4.1.5 sidebar changes leave the sink as it was in 4.1.4.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only, in one browser (Chromium 140); no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **4.1** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N`

- **AV:N** Registration, the proxy and the UI are plain HTTP endpoints.
- **AC:L** No condition beyond the stated preconditions once an instance is registered; SSRF protection is opt-in.
- **PR:L** Registration needed an authenticated user in the lab. An unsecured SBA (PR:N) was not run.
- **UI:R** The operator has to open the instance in the UI; no click on the injected element is needed.
- **S:C** Script supplied through an instance runs on the SBA origin with the operator's session.
- **C:L** In the same lab, script on the SBA origin read the CSRF cookie and another instance's synthetic `/actuator/env` through the proxy.
- **I:N** No state-changing request was demonstrated.
- **A:N** None demonstrated.

## Credit

thientc (VinSOC)
