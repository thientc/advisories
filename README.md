# Security advisories

Advisories for vulnerabilities I found and reported, by thientc (VinSOC).
Contact: thientc84@gmail.com

Times are UTC and come from my research log. "Found" is when the issue was first recorded as a lead and "Confirmed" is when I reproduced it in the lab. A dash means the time was not recorded. CVSS is the 3.1 base score I proposed; the vendor or CNA may score it differently.

## mall

- Source: https://github.com/macrozheng/mall (no published package; deployed from source)
- Tested version: master `dcaa93b` (latest release at test time: 1.0.3)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [MALL-2026-01](mall/MALL-2026-01-jwt-alg-none-auth-bypass.md) | Unauthenticated login as any user via unsigned (alg:none) JWT | 9.8 | 2026-11-17 16:35 | 2026-11-17 23:41 | pending (requested from MITRE 2026-11-22) | Vendor contacted 2026-11-18 via public issue [#1042](https://github.com/macrozheng/mall/issues/1042) (contact request only; no private channel), no reply as of 2026-11-22 |
| [MALL-2026-02](mall/MALL-2026-02-cart-client-price.md) | Client-supplied cart price becomes the order and payment amount | 6.5 | 2026-11-17 17:14 | 2026-11-17 17:14 | pending (requested from MITRE 2026-11-22) | Vendor contacted 2026-11-18 via public issue [#1042](https://github.com/macrozheng/mall/issues/1042) (contact request only; no private channel), no reply as of 2026-11-22 |
| [MALL-2026-03](mall/MALL-2026-03-cart-negative-quantity.md) | Negative cart quantity lowers the order total and inflates stock | 6.5 | 2026-11-17 17:14 | 2026-11-17 17:14 | pending (requested from MITRE 2026-11-22) | Vendor contacted 2026-11-18 via public issue [#1042](https://github.com/macrozheng/mall/issues/1042) (contact request only; no private channel), no reply as of 2026-11-22 |
| [MALL-2026-04](mall/MALL-2026-04-mall-search-missing-auth.md) | Missing authentication on mall-search index management | 6.5 | 2026-11-17 23:43 | 2026-11-17 23:43 | pending (requested from MITRE 2026-11-22) | Vendor contacted 2026-11-18 via public issue [#1042](https://github.com/macrozheng/mall/issues/1042) (contact request only; no private channel), no reply as of 2026-11-22 |
| [MALL-2026-05](mall/MALL-2026-05-weblogaspect-credentials-in-logs.md) | Passwords, verification codes and JWTs written to the application log | 4.4 | 2026-11-17 23:43 | 2026-11-17 23:43 | pending (requested from MITRE 2026-11-22) | Vendor contacted 2026-11-18 via public issue [#1042](https://github.com/macrozheng/mall/issues/1042) (contact request only; no private channel), no reply as of 2026-11-22 |
| [MALL-2026-06](mall/MALL-2026-06-collection-id-overwrite.md) | Member can overwrite other members' collection documents by id | 3.1 | 2026-11-17 17:14 | 2026-11-17 17:14 | pending (requested from MITRE 2026-11-22) | Vendor contacted 2026-11-18 via public issue [#1042](https://github.com/macrozheng/mall/issues/1042) (contact request only; no private channel), no reply as of 2026-11-22 |

## XXL-JOB

- Source: https://github.com/xuxueli/xxl-job (`xxl-job-admin`; executor library on Maven Central as `com.xuxueli:xxl-job-core`)
- Tested version: 3.5.0 (tag `3bebfc16`, latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [XXL-JOB-2026-01](xxl-job/XXL-JOB-2026-01-jobinfo-update-cross-group.md) | Cross-group job takeover through /jobinfo/update | 7.1 | 2026-11-02 01:45 | 2026-11-02 01:46 | pending | Vendor notified 2026-11-02, no reply; CVE requested from MITRE on 2026-11-17 |
| [XXL-JOB-2026-02](xxl-job/XXL-JOB-2026-02-openapi-token-not-bound-to-group.md) | OpenAPI access token not bound to its executor group | 8.3 | 2026-11-02 01:45 | 2026-11-02 01:46 | pending | Vendor notified 2026-11-02, no reply; CVE requested from MITRE on 2026-11-17 |
| [XXL-JOB-2026-03](xxl-job/XXL-JOB-2026-03-user-pagelist-session-token.md) | Admin user list returns other users' session tokens | 2.7 | 2026-11-02 01:45 | 2026-11-02 01:47 | pending | Vendor notified 2026-11-02, no reply |

## Sa-Token

- Source: https://github.com/dromara/Sa-Token · Maven `cn.dev33:sa-token-*`
- Tested version: 1.46.0 (latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [SA-TOKEN-2026-01](sa-token/SA-TOKEN-2026-01-encoded-path-saroute-bypass.md) | Percent-encoded letters in the path bypass SaRouter rules in the Spring Boot 2 starter | 6.5 | — | 2026-11-17 10:23 | pending (requested from MITRE 2026-11-22) | Reported 2026-11-17 via GitHub (GHSA-vg7p-x828-qvmx); in triage, no reply as of 2026-11-22 |
| [SA-TOKEN-2026-02](sa-token/SA-TOKEN-2026-02-sso-ticket-fragment-allow-url-bypass.md) | SSO redirect check ignores the URL fragment, so the login ticket can be sent to an attacker page | 8.1 | — | 2026-11-17 14:47 | pending (requested from MITRE 2026-11-22) | Reported 2026-11-17 via GitHub (GHSA-g2m5-xwp5-ch3w); in triage, no reply as of 2026-11-22 |
| [SA-TOKEN-2026-03](sa-token/SA-TOKEN-2026-03-class-level-annotations-skipped.md) | Class-level @SaCheckRole / @SaCheckLogin is not applied to handler methods inherited from a base controller | 4.8 | — | 2026-11-17 14:47 | pending (requested from MITRE 2026-11-22) | Reported 2026-11-17 via GitHub (GHSA-2jcm-vmf7-g4mx); in triage, no reply as of 2026-11-22 |
| [SA-TOKEN-2026-04](sa-token/SA-TOKEN-2026-04-sign-nonce-stored-before-signature.md) | sa-token-sign stores the nonce before checking the signature, allowing unauthenticated memory exhaustion | 7.5 | — | 2026-11-17 14:47 | pending (requested from MITRE 2026-11-22) | Reported 2026-11-17 via GitHub (GHSA-445w-cfq4-vjj2); in triage, no reply as of 2026-11-22 |
| [SA-TOKEN-2026-05](sa-token/SA-TOKEN-2026-05-sso-logout-callback-host-ssrf.md) | SSO logout callback is built from the Host header and fetched by the SSO server without validation (blind SSRF) | 5.0 | — | 2026-11-17 14:47 | pending (requested from MITRE 2026-11-22) | Reported 2026-11-17 via GitHub (GHSA-g4g9-mxgm-fqcg); in triage, no reply as of 2026-11-22 |
| [SA-TOKEN-2026-06](sa-token/SA-TOKEN-2026-06-oauth2-doconfirm-consent-csrf.md) | /oauth2/doConfirm has no CSRF protection, letting a registered client skip the consent screen | 3.7 | — | 2026-11-17 14:48 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

## Better Search Replace

- Source: https://wordpress.org/plugins/better-search-replace/
- Tested version: see advisory

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [BSR-2026-01](better-search-replace/BSR-2026-01-main-site-admin-to-super-admin.md) | On multisite, a main-site administrator can make themself network super admin by rewriting `wp_sitemeta` | 9.1 | 2026-11-03 08:30 | — | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

## miniOrange SAML 2.0 Single Sign On

- Source: https://wordpress.org/plugins/miniorange-saml-20-single-sign-on/
- Tested version: 6.2.2 (latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [MINIORANGE-SAML-2026-01](miniorange-saml/MINIORANGE-SAML-2026-01-nameid-sanitize-account-collision.md) | SAML NameID is run through `sanitize_text_field()` before account matching, so a different signed identity logs in as an existing administrator | 7.5 | 2026-11-18 06:34 | 2026-11-18 06:49 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |
| [MINIORANGE-SAML-2026-02](miniorange-saml/MINIORANGE-SAML-2026-02-unauth-oversize-response-object-injection.md) | Unauthenticated PHP object injection through an oversize test-mode SAMLResponse, triggered when an administrator exports the plugin configuration | 7.5 | — | 2026-11-18 07:19 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

## SiteOrigin Widgets Bundle

- Source: https://wordpress.org/plugins/so-widgets-bundle/
- Tested version: 1.76.0 (latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [SO-WIDGETS-BUNDLE-2026-01](so-widgets-bundle/SO-WIDGETS-BUNDLE-2026-01-contributor-lfi-price-table-theme.md) | Contributor can include any existing .php file through the Price Table `design.theme` value in the `[siteorigin_widget]` shortcode | 7.5 | — | 2026-11-18 07:18 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

## uListing

- Source: https://wordpress.org/plugins/ulisting/
- Tested version: 2.2.0 (latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [ULISTING-2026-01](ulisting/ULISTING-2026-01-unauth-listing-deletion.md) | Unauthenticated permanent deletion of listings through `/1/api/ulisting-user/deletelisting` | 7.5 | 2026-10-30 02:19 | 2026-10-30 02:25 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

## Product Options and Price Calculation Formulas for WooCommerce (Uni CPO)

- Source: https://wordpress.org/plugins/uni-woo-custom-product-options/
- Tested version: 4.9.71 (latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [UNI-CPO-2026-01](uni-cpo/UNI-CPO-2026-01-guest-order-line-product-substitution.md) | Guest can swap the product on an order line for another product while paying the cheap product's price | 8.2 | — | 2026-11-18 07:19 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

## WPAdverts

- Source: https://wordpress.org/plugins/wpadverts/
- Tested version: 2.3.5 (latest release at test time)

| ID | Issue | CVSS 3.1 | Found (UTC) | Confirmed (UTC) | CVE | Status |
|---|---|---|---|---|---|---|
| [WPADVERTS-2026-01](wpadverts/WPADVERTS-2026-01-unauth-stored-xss-phone-button.md) | Unauthenticated stored XSS through the ad Phone Number in the Contact Form "Call" button | 7.2 | 2026-10-30 09:04 | 2026-10-30 09:04 | pending (requested from MITRE 2026-11-22) | Not reported to the vendor as of 2026-11-22 |

All testing was done in a local lab with test accounts and test data. No production system was tested.
