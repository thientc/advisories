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
