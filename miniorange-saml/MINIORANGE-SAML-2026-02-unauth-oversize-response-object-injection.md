# MINIORANGE-SAML-2026-02: Unauthenticated PHP object injection through an oversize test-mode SAMLResponse, triggered when an administrator exports the plugin configuration

- Product: SAML Single Sign On – SSO Login by miniOrange (https://wordpress.org/plugins/miniorange-saml-20-single-sign-on/); source taken from the wordpress.org release, no official GitHub repository known to me
- Affected: 6.2.2, the latest release on wordpress.org when checked on 2026-11-18
- CVSS 3.1: 7.5 (High) `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` (scored as PHP object injection with an assumed POP chain; none is known, see Severity)
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

An anonymous POST with `RelayState=testValidate` and a `SAMLResponse` longer than the plugin's size cap (734,008 bytes with the default settings) gets the test-configuration error page WPSAMLERR040. That page stores the raw POST value, after only `sanitize_text_field()`, in the option `MO_SAML_RESPONSE`. The size check runs before any base64 or XML check, so the stored value can be a PHP serialized object. When an administrator later clicks "Export Plugin Configuration", `mo_saml_get_configuration_array()` passes each option through `maybe_unserialize()`, and the anonymous string is unserialized in the administrator's request. In my lab an attacker-chosen class was instantiated during the export, and with a lab-only test class loaded its `__wakeup()` ran.

## Details

Write, no authentication and no nonce:

1. `login.php:64` runs the ACS handler on `init`. It reads `$_POST['SAMLResponse']` (`class-mo-saml-login-validate.php:119`, `:126`), and only refuses if no IdP certificate is configured (`:120-123`). `RelayState` comes from the POST (`:133-135`), so the sender can choose `testValidate`.
2. The POST cap is `ceil( ( ceil( 524288 * 4 / 3 ) + 4 ) * 1.05 )` = 734,008 bytes with the default limit and no `mo_saml_max_saml_response_length` filter (`:140-153`). `mo_saml_reject_oversize_saml_response_post()` runs at `:155`, before base64 decoding at `:159-161`.
3. Over the cap with `testValidate`, it calls `mo_saml_display_test_config_error_page( WPSAMLERR040 )` (`class-mo-saml-utilities.php:450-454` → `:480-483`). That page calls `mo_saml_download_logs()` (`mo-saml-settings-page.php:123` → `:169`).
4. `mo_saml_download_logs()` (`mo-saml-settings-page.php:230-236`) does `update_option( MO_SAML_RESPONSE, sanitize_text_field( wp_unslash( $_POST['SAMLResponse'] ) ) )` and sets `MO_SAML_TEST_STATUS` to 0 (`:242`). WordPress serializes an already-serialized string again on store, so `get_option()` hands back the original serialized string.

Trigger, administrator:

5. "Export Plugin Configuration" on the Service Provider tab posts `option=mo_saml_export` with the `mo_saml_export` nonce, handled on `admin_init` (`mo-saml-import-export.php:15`, `:39-49`).
6. The `Test_Configuration` group, which includes `MO_SAML_RESPONSE`, is exported whenever `MO_SAML_TEST_STATUS !== 1` (`mo-saml-import-export.php:25-28`). The write in step 4 set it to 0.
7. `mo_saml_get_configuration_array()` (`mo-saml-import-export.php:99-106`) does `maybe_unserialize( get_option( $value ) )` for each option. That is an unrestricted `unserialize()` of the anonymous string.

The same function backs the `mo-saml/show-sso-configurations` ability (`handlers/class-mo-saml-register-abilities.php:300-352`, `manage_options`). Abilities are registered only when the plugin's Abilities API option is switched on (`:42-46`), which it is not by default.

Preconditions: an IdP is configured in the plugin. The payload is longer than the cap but within PHP `post_max_size` (8M in my lab) and the database packet limit. It must also come through `sanitize_text_field()` unchanged, so no `<`, no `%XX` sequences and no line breaks or runs of whitespace, which an ordinary serialized object meets. Finally, an administrator runs the configuration export, or the ability on a site that has enabled it.

## PoC

Setup: WordPress 7.1.4, PHP 8.3, the plugin 6.2.2 configured with one IdP and its certificate. Users `admin` (administrator) and `sub1`. At the start `MO_SAML_RESPONSE`, `MO_SAML_TEST` and `MO_SAML_TEST_STATUS` were absent.

Control, a 31-byte invalid value, no cookies:

```sh
curl -s -D - --data-urlencode "SAMLResponse@control-small.txt" -d 'RelayState=testValidate' http://<host>/
# HTTP/1.1 500, <title>WPSAMLERR017 Invalid XML
```

Below the cap the value is decoded and parsed, and nothing was stored.

Step A, a class that exists nowhere. `payload-A.txt` is 800,051 bytes:

```
O:17:"MoSamlL15Mk7q2xZt":1:{s:3:"pad";s:800000:"AAAA...AAAA";}
```

```sh
curl -s -D - --data-urlencode "SAMLResponse@payload-A.txt" -d 'RelayState=testValidate' http://<host>/
# HTTP/1.1 200 OK, WPSAMLERR040 "The SAML Response exceeded the maximum allowed size"
```

Afterwards `MO_SAML_TEST_STATUS` = `0`, `strlen( get_option( 'MO_SAML_RESPONSE' ) )` = 800051, and `is_serialized()` is true.

Then, logged in as `admin`, load `/wp-admin/admin.php?page=mo_saml_settings&tab=service_provider`, take the `mo_saml_export` nonce from the export form, and POST `option=mo_saml_export&_wpnonce=<nonce>` to the same URL. The response is HTTP 200 with `Content-Disposition: attachment; filename=miniorange-saml-config.json`, and contains:

```json
"Test_Configuration": { "SAML_RESPONSE": { "__PHP_Incomplete_Class_Name": "MoSamlL15Mk7q2xZt", "pad": "AAAA..." } }
```

So the anonymous string was unserialized into an object during the export.

Step B, magic method. To show that methods of the instantiated class run, I loaded a lab-only stand-in class as a mu-plugin:

```php
class L15LabGadget { public $m; public function __wakeup() { file_put_contents( '/tmp/l15-' . $this->m, 'hit' ); } }
```

With the options cleared and no marker file present, a baseline export produced no `SAML_RESPONSE` and no marker. I then sent an anonymous POST of `O:12:"L15LabGadget":2:{s:1:"m";s:4:"poc1";s:3:"pad";s:800000:"AAAA...";}` (800,065 bytes) the same way, and got HTTP 200 WPSAMLERR040, with no marker yet. After the same admin export, the JSON had `"SAML_RESPONSE": {"m":"poc1","pad":"AAAA..."}` and `/tmp/l15-poc1` existed, owned by `www-data`, containing `hit`.

Ability path: with the Abilities API option switched on for this step, the same stored payload and `GET /?rest_route=/wp-abilities/v1/abilities/mo-saml/show-sso-configurations/run` as `admin` with a REST nonce returned HTTP 200 `"success":true`, and the marker file was written again.

The write and export ran three times in total: Step A, Step B, and a repeat of Step B during the fix test.

## Impact

One anonymous request stores an arbitrary serialized PHP value (about 800 KB in my test) in the plugin's options, although the plugin's own size check rejected the response. When an administrator uses the plugin's normal configuration export, the value is unserialized in that administrator's request: a class the attacker picks is instantiated with properties the attacker picks, and its magic methods run.

What this leads to depends on which classes are loaded on the site. The plugin itself defines no `__wakeup`, `__destruct`, `__toString`, `__unserialize`, `__call`, `__get` or `__set`, and I did not look for or build a gadget chain in WordPress core 7.1.4 or elsewhere. The class used in Step B is a stand-in. The exported JSON goes to the administrator, not to the attacker. I did not test how a real administrator would be led to run the export.

## Suggested fix

Two independent changes, either of which stopped the lab case:

1. In `mo_saml_get_configuration_array()`, don't expand `MO_SAML_RESPONSE` at all (export its length instead), and replace `maybe_unserialize()` with `unserialize( $v, array( 'allowed_classes' => false ) )` for serialized strings, keeping the result only if it is an array.
2. In `mo_saml_download_logs()`, don't store the raw POSTed `SAMLResponse`; store a length and hash instead.

Separately, the `testValidate` error paths probably should not write anything unless an administrator's test is actually in progress. I have not tested that change for this case.

I tested each change on its own in the lab with the stand-in class loaded. With change 1 and the poisoned option still stored, the export returned HTTP 200 with `"SAML_RESPONSE": "[omitted: 800065 bytes]"` and no marker. A clean export was byte-identical to the unpatched one. With change 2, the anonymous POST still got WPSAMLERR040 but the stored value was a 95-byte `[omitted: 800065 bytes sha256=…]` string, and the export wrote no marker. I did not test both changes together, the ability path on the patched code, or the effect on a real stored test response.

## Affected versions

- Tested and affected: 6.2.2 (wordpress.org release).
- Earlier releases were not tested.
- Fixed in: no fixed release known.

Tested on 2026-11-18 on a local WordPress lab with test accounts and synthetic data only; no live site was tested.

## Severity

CVSS 3.1 base score **7.5** (High): `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`

This follows the usual convention for PHP object injection: impact is scored as if a POP chain is available, and AC:H records that none is known.

- **AV:N** The write is an HTTP POST to any front-end URL.
- **AC:H** Impact beyond instantiation needs a usable gadget among the classes loaded on the site, which the attacker doesn't control and which I have not shown for core or this plugin.
- **PR:N** The write needs no account and no nonce.
- **UI:R** An administrator has to run the configuration export, or the ability where it is enabled.
- **S:U** The object lives in the same WordPress PHP process.
- **C:H / I:H / A:H** Assumed impact of a gadget chain in an administrator request. Not demonstrated.

If you score only what was demonstrated (object instantiation and magic-method calls, no known chain), `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` gives 4.2.

## Credit

thientc (VinSOC)
