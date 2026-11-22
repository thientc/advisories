# WPADVERTS-2026-01: Unauthenticated stored XSS through the ad Phone Number in the Contact Form "Call" button

- Product: WPAdverts – Classifieds Plugin (https://wordpress.org/plugins/wpadverts/); source published on the wordpress.org plugin SVN, no official GitHub repository known to me
- Affected: 2.3.5, the latest release on wordpress.org when checked on 2026-11-18
- CVSS 3.1: 7.2 (High) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N`
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

The Phone Number a visitor enters when posting an ad is stored without sanitization and printed without escaping inside the "Call" button that the Contact Form module adds to the single-ad block template. Anonymous posting is the default, so a logged-out visitor can publish an ad whose phone number carries markup with an event handler. In my lab that handler ran for a logged-out visitor and for a logged-in administrator who opened the ad.

This needs the bundled Contact Form module, which is off on a fresh install.

## Details

1. The `adverts_phone` field (`includes/defaults.php:74-85`) has only a `string_length` (min 5) validator and no filter. `adverts_save_single()` stores it as-is (`includes/functions.php:1874`).
2. With the Contact Form module on, `get_phone_button()` in `addons/contact-form/includes/class-block-details.php` builds the button HTML from the raw value (line 110):

```php
"html" => sprintf( __('Call <span data-ph1="%s" class="wpadverts-phone">%s</span>', "wpadverts"), $ph1, $phone ),
```

3. `wpadverts_block_button()` echoes `$args["html"]` unescaped (`includes/functions-blocks.php:290`) and prints the button attributes with a bare `sprintf( '%s="%s"', $k, $v )` (line 272).

The installer sets single ads to render with block templates (`wpadverts.php:765-766`). The default single-ad template ends with the `wpadverts/single-contact` block, which shows the phone button when a phone number is present. The installer creates the Publish page (with the `wpadverts/publish` block) as a draft; once the owner publishes it, that block by default requires no login and no moderation (`class-publish-engine.php:248-253`, `573-580`). The classic shortcode template and the single-data-table block escape the phone; this button doesn't.

Preconditions: Contact Form module enabled; the Publish page published; single ads on block templates (the installer default).

## PoC

Setup: WordPress 7.1.4, PHP 8.3, WPAdverts 2.3.5, Twenty Twenty-One theme. As the administrator, enable the Contact Form module (Classifieds > Extensions) and publish the Publish page the installer created. Everything else at defaults.

1. Logged out, open the Publish page and fill in name, email, title, category and description with ordinary values. As Phone Number enter:

```
555<b id="wpaPhoneMark">M</b><img src=x onerror="document.title='WPA-PHONE-XSS'">
```

2. Wait out the form's time trap, submit to Preview, then Publish from the preview. The ad is published at once with author 0, and `adverts_phone` is stored exactly as entered.
3. Open the ad page (`GET /advert/<slug>/`). The `<b id="wpaPhoneMark">` element and the `<img ... onerror=...>` element appear unescaped inside the `wpadverts-phone` span of the `wpadverts-reveal-phone` button.
4. In a headless browser the page title became `WPA-PHONE-XSS` and the marker element was in the DOM, both for a logged-out visitor and for the logged-in administrator (admin bar present).

Control: an ad posted the same way with the phone `555 0100 200` rendered as `Call <span data-ph1="555" class="wpadverts-phone">555 0100 200</span>`, and the title stayed the ad's normal title for both users.

## Impact

A visitor without an account can store markup in an ad that runs script in the browser of anyone who opens that ad, including an administrator reviewing it. My test only changed `document.title`; I did not try any action in the administrator's session, such as creating a user or changing settings, so I can't say from testing what such a payload would achieve. All data was synthetic.

I scored AC:L because the Contact Form module is an ordinary bundled option the site owner turns on, not something the attacker has to overcome. Counting it as a special condition, AC:H gives 6.4.

## Suggested fix

Escape the value where the button HTML is built (`esc_attr( $ph1 )`, `esc_html( $phone )`, also in the reveal-on-click branch at `class-block-details.php:89`), and escape attribute names and values in `wpadverts_block_button()`. A sanitizer on the `adverts_phone` field would add a second layer.

With the two escaping changes applied in my lab, the same ad rendered the payload as text (`555&lt;b id=&quot;wpaPhoneMark&quot;&gt;...`), the handler did not run for either user, and the control ad looked the same as before.

## Affected versions

- Tested and affected: 2.3.5 (wordpress.org archive, SHA-256 7b8e611743d6fd5d7cfd33d47afac85d91674bc5f604c186eaab1501708e0ce9).
- From reading older releases: the phone value was escaped elsewhere in 2.3.2 (AJAX contact reveal) and 2.3.5 (single-data-table block), but `get_phone_button()` and `wpadverts_block_button()` are unchanged from 2.3.1 to 2.3.5. I only ran 2.3.5.
- Fixed in: no fixed release known.

The public WPAdverts entries I checked on 2026-10-30 were all fixed in 2.3.5 or earlier, so I don't think this is one of them.

Tested on a local WordPress lab with test accounts and synthetic data only; no live site was tested.

## Severity

CVSS 3.1 base score **7.2** (High): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N`

- **AV:N** Ad submission over HTTP.
- **AC:L** Standard publish form; the only condition is an enabled bundled module.
- **PR:N** Anonymous posting is the default.
- **UI:N** The script runs when the ad page is opened; no further click.
- **S:C** The script runs in other users' browsers, administrators included.
- **C:L / I:L** What the viewer's session can read or do. Not demonstrated beyond the title marker.
- **A:N** Not claimed.

## Credit

thientc (VinSOC)
