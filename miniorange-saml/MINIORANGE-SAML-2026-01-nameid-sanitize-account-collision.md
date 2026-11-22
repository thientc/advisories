# MINIORANGE-SAML-2026-01: SAML NameID is run through `sanitize_text_field()` before account matching, so a different signed identity logs in as an existing administrator

- Product: SAML Single Sign On – SSO Login by miniOrange (https://wordpress.org/plugins/miniorange-saml-20-single-sign-on/); source taken from the wordpress.org release, no official GitHub repository known to me
- Affected: 6.2.2, the latest release on wordpress.org when checked on 2026-11-18
- CVSS 3.1: 7.5 (High) `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

After the ACS handler verifies a SAML response's signature, it replaces the NameID with `sanitize_text_field( $nameid )` (`class-mo-saml-login-validate.php:314`). In the default "Identify user by: Email" mode, when the assertion carries no mapped email attribute, that rewritten value is used to find an existing WordPress account by email (`:388-389`, `:570-573`). `sanitize_text_field()` strips `<...>` spans, collapses and trims whitespace, and deletes `%XX` octets without decoding them. So signed NameIDs such as `victimadmin%41@lab.test`, `victimadmin@lab.test <x@evil.test>`, `victimadmin@lab.test<b>` and `victimadmin@lab.test%0A` all become `victimadmin@lab.test`. In my lab each of those four assertions was logged in as the existing administrator with that email.

## Details

- `login.php:64` hooks `Mo_Saml_User_Login_Handler::mo_saml_handle_login_validate` on `init`, which builds `Mo_SAML_Login_Validate` (`handlers/class-mo-saml-user-login-handler.php:57`) and reads `$_POST['SAMLResponse']` (`class-mo-saml-login-validate.php:119`).
- Issuer, audience, signature against the configured IdP certificate, and replay are all checked (`:256`, `:258-305`, `:309`). Unsigned responses and responses signed by another key are rejected. This bug is about what happens to a correctly signed assertion afterwards.
- `:312-314`:

  ```php
  $ssoemail        = current( current( $assertions )->mo_saml_get_name_id() );
  $attrs           = current( $assertions )->mo_saml_get_attributes();
  $attrs['NameID'] = array( '0' => sanitize_text_field( $ssoemail ) );
  ```

- `:386-390`: `$user_email` is the mapped email attribute if one is present, otherwise `$attrs['NameID'][0]`, the sanitized value. Any RelayState other than `testValidate` then calls `mo_saml_login_user()` (`:399-404`). `Mo_SAML_Utilities::mo_saml_get_identify_user_by()` (`class-mo-saml-utilities.php:1214-1219`) returns email unless the site explicitly chose username.
- `mo_saml_login_user()` (`:570-573`): `email_exists( $user_email )` → `get_user_by( 'email', $user_email )` → that user's ID. Nothing compares the stored email with the raw NameID, and there is no role check on this branch. The only administrator check (`:604`) only stops the default role being written over an admin. `wp_set_auth_cookie( $user_id, true )` follows at `:663`.

In WordPress core, `_sanitize_text_fields()` calls `wp_strip_all_tags()` when the value contains `<`, collapses `[\r\n\t ]+` to a space and trims, then loops deleting `%[a-f0-9]{2}` (`wp-includes/formatting.php:5717-5743` in 7.1.3). It is meant for cleaning text for storage and display, so it does not give a canonical form of an identity.

The 6.0.0 changelog says "Improved existing WordPress user identification during SSO login to prevent incorrect account access". The sanitization before lookup is still there in 6.2.2.

Preconditions: an IdP is configured in the plugin; "Identify user by" is Email (the default); no email attribute mapping is in effect for the assertion, so the NameID is used; and a WordPress administrator exists whose email is the sanitized form of a NameID the attacker can get the IdP to sign.

That last point is the real limit. The attacker needs an account at the trusted IdP whose NameID they can choose with characters such as `%`, `<` or a trailing space, for example a self-service username or email that the IdP does not validate strictly. My lab used a mock IdP signing with the trusted lab key. That shows how the plugin handles such a NameID, but not that any particular IdP product will issue one. I did not test a real IdP.

## PoC

Setup: WordPress 7.1.4, PHP 8.3, the plugin 6.2.2 configured with one IdP (issuer `https://idp.lab.test/saml/metadata`) and its signing certificate, no attribute mapping, "Identify user by" left at Email. Users before every run:

```
ID,user_login,user_email,roles
1,admin,admin@lab.test,administrator
2,victimadmin,victimadmin@lab.test,administrator
3,sub1,sub1@lab.test,subscriber
```

For each case the mock IdP signed both the Response and the Assertion with the trusted key, using a fresh assertion ID and no attributes. The response was POSTed to the site:

```http
POST / HTTP/1.1
Host: <host>
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64 signed response with the NameID below>
```

No RelayState was sent. Any value other than `testValidate` takes the same login branch.

Then `/wp-admin/profile.php` was loaded with the returned cookies.

| Signed NameID | ACS response | Session user | Users table |
|---|---|---|---|
| `victimadmin%41@lab.test` | 302, `wordpress_logged_in_…=victimadmin` | `victimadmin` / `victimadmin@lab.test`, admin menus shown | unchanged |
| `victimadmin@lab.test <x@evil.test>` | 302, `wordpress_logged_in_…=victimadmin` | `victimadmin` | unchanged |
| `victimadmin@lab.test<b>` | 302, `wordpress_logged_in_…=victimadmin` | `victimadmin` | unchanged |
| `victimadmin@lab.test%0A` (literal `%0A`) | 302, `wordpress_logged_in_…=victimadmin` | `victimadmin` | unchanged |

None of the four NameIDs is the string `victimadmin@lab.test`. No new account was created in any case.

Controls in the same session:

- NameID `nobody-c1@lab.test`: 302, a new subscriber `nobody-c1@lab.test` was created and logged in.
- NameID `victim%61dmin@lab.test`: 302, a new subscriber `victimdmin@lab.test` was created. The octet is deleted, not decoded, and a non-colliding value gets its own account.
- Unsigned response: HTTP 500 `WPSAMLERR003 Unsigned Response or Assertion`.
- Response signed by a different key: HTTP 500 `WPSAMLERR004 Mismatch in Certificate`.

Each collision case ran once.

## Impact

Someone holding an IdP identity whose NameID differs from a WordPress administrator's email only by characters `sanitize_text_field()` removes gets a session as that administrator. In the lab the session had the full administrator menu (Users, Plugins). Nothing is created or changed in the users table, so the login looks like the administrator's own SSO login.

I did not show that any production IdP issues such NameIDs to a low-privileged user. I also did not test multisite, multiple IdPs or the premium plugin.

I also saw case and accent variants (`VICTIMADMIN@lab.test`, `vìctimadmin@lab.test`) match `victimadmin`, both as NameID and through a mapped email attribute. That comes from the database collation and core lookups rather than from this plugin's sanitization, so I am not counting it here. The fix below covers it anyway.

## Suggested fix

Keep the raw signed NameID for matching and provisioning, and use the sanitized copy only for display and logs. In `mo_saml_login_user()`, reject an identifier that is not already canonical (for email: `is_email()` and equal to its `sanitize_email()` and `sanitize_text_field()` forms), and after `get_user_by()` require an exact `hash_equals()` match between the stored `user_email` or `user_login` and the raw value.

I tested this in the lab. With the patch, `victimadmin%41@lab.test`, `victimadmin@lab.test <x@evil.test>` and `vìctimadmin@lab.test` got HTTP 500 `WPSAMLERR024 Invalid SAML Assertion` with no login cookie. A case-changed mapped email attribute and case or accent variants in username mode were also rejected. Exact logins as `victimadmin` and `sub1` still worked, by NameID, mapped email attribute and username, and no rejected request created a user. I did not re-run the `<b>` and `%0A` cases or a new-user provisioning case on the patch. The exact comparison is case-sensitive, so an IdP that sends existing users' emails in a different case would stop matching. Whether to compare case-insensitively is your call.

## Affected versions

- Tested and affected: 6.2.2 (wordpress.org release).
- Earlier releases were not tested.
- Fixed in: no fixed release known.

Tested on 2026-11-18 on a local WordPress lab with a mock IdP, test accounts and synthetic data only; no live site and no real IdP were tested.

## Severity

CVSS 3.1 base score **7.5** (High): `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`

- **AV:N** The ACS handler runs for a POST to any front-end URL.
- **AC:H** The trusted IdP must sign an attacker-chosen, non-canonical NameID that collides after sanitization. That depends on IdP configuration the attacker doesn't control, and I have not established it for any real IdP.
- **PR:L** The attacker needs an account at the trusted IdP, though not on WordPress.
- **UI:N** No victim action.
- **S:U** The result is a session on the same WordPress site.
- **C:H / I:H / A:H** A full administrator session was obtained. Reading all data, changing users and settings, and installing plugins follow from that role; I did not exercise them.

## Credit

thientc (VinSOC)
