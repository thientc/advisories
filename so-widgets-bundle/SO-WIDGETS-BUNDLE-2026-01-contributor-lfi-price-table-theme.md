# SO-WIDGETS-BUNDLE-2026-01: Contributor can include any existing .php file through the Price Table `design.theme` value in the `[siteorigin_widget]` shortcode

- Product: SiteOrigin Widgets Bundle (https://wordpress.org/plugins/so-widgets-bundle/); development repository https://github.com/siteorigin/so-widgets-bundle
- Affected: 1.76.0, the latest release on wordpress.org when checked on 2026-11-18
- CVSS 3.1: 7.5 (High) `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

The `[siteorigin_widget]` shortcode builds a widget instance from JSON in the shortcode body and calls the widget's `widget()` method without running `update()`. For the Price Table widget, `instance['design']['theme']` becomes the template name, and the bundle includes `tpl/<theme>.php` after only a `realpath()` and a `.php` suffix check. A Contributor who puts a `../` path in `theme` in their own draft and previews it makes WordPress include that `.php` file. In my lab this included and ran a probe file I had placed in `/tmp`.

Two conditions apply. The Price Table widget must be active, which it is not on a fresh install. And the included file must be an existing `.php` file at a path the attacker can name; a Contributor cannot upload one.

## Details

1. `base/inc/shortcode.php:27-31` matches `value="..."` in the shortcode content and runs `json_decode( html_entity_decode( ... ) )` on it. Lines 33-47 pass `args` and `instance` only through `siteorigin_widget_shortcode_escape_widget_data()`, which applies `esc_html` to strings and leaves dots and slashes alone. Line 51 calls `widget()` with that instance. There is no capability check on this path.
2. `widgets/price-table/price-table.php:428-430` returns `get_style_name()` as the template name, and `get_style_name()` (lines 472-478) returns the raw `$instance['design']['theme']`.
3. `base/siteorigin-widget.class.php:215-228`:

```php
$template_file = siteorigin_widget_get_plugin_dir_path( $this->id_base ) . $this->get_template_dir( $instance ) . '/' . $this->get_template_name( $instance ) . '.php';
...
$template_file = realpath( $template_file );
if ( substr( $template_file, -4 ) != '.php' ) {
    $template_file = false;
}
...
@ include $template_file;
```

Nothing checks that the resolved path stays inside the widget's `tpl/` directory.

Since 1.74.0, `update()` strips values the widget doesn't declare, but the shortcode path never calls it. Wordfence lists an earlier "Contributor+ LFI via 'theme' Parameter" fixed in 1.74.0. I don't know which code path that entry covered, so this may be a remaining path of the same issue rather than a separate one.

## PoC

Setup: WordPress 7.1.3, PHP 8.3, SiteOrigin Widgets Bundle 1.76.0, otherwise default settings. As the administrator I activated the Price Table widget (I used wp-cli, `SiteOrigin_Widgets_Bundle::single()->activate_widget('price-table')`; the same setting is under Plugins > SiteOrigin Widgets) and created a Contributor account. As a stand-in for a `.php` file that already exists on the server, I placed `/tmp/lab-probe.php` containing `<?php echo "PROBE-<random>";` (a fresh random marker per run).

1. As the Contributor, create a draft through the REST API (`POST /?rest_route=/wp/v2/posts` with the Contributor's REST nonce, `"status":"draft"`) whose content is:

```
[siteorigin_widget class="SiteOrigin_Widget_PriceTable_Widget"]<li value="{&quot;instance&quot;:{&quot;design&quot;:{&quot;theme&quot;:&quot;../../../../../../../../../tmp/lab-probe&quot;}}}">x</li>[/siteorigin_widget]
```

The widget appends `.php`. The stored raw content came back identical, so the `<li value>` carrier passes Contributor kses. The `content.rendered` field of this REST response already contained the probe marker.

2. As the Contributor, preview the draft:

```http
GET /?p=<draft id>&preview=true HTTP/1.1
Host: <host>
Cookie: <contributor session cookies>
```

The response was HTTP 200 and contained `PROBE-<random>`, printed by the probe file.

Controls: the same draft with `"theme":"atom"` rendered the normal price table and no marker; a `theme` pointing at a file that does not exist rendered no marker. I ran the attack and both controls twice, with a new random marker in the probe each time.

## Impact

A Contributor can make WordPress include and run any existing `.php` file whose path they can name, from a preview of their own draft or from the REST save itself. The included code runs as the web server user inside WordPress.

What I showed is inclusion of a benign file that I put on the server myself. A Contributor has no `upload_files` capability, so running attacker-written code needs a separate way to get a `.php` file with controlled content onto the server, or an existing PHP file that does something harmful when included. I did not chain either and did not survey which stock core or plugin files would be useful. The C/I/A:H rating is the case where such a file is available, which is also why I set AC:H. Where `open_basedir` is set it limits which files can be reached. If an Editor published the post, the include would presumably run on the public page too; I did not test that.

## Suggested fix

After `realpath()`, require the path to start with `realpath( siteorigin_widget_get_plugin_dir_path( $this->id_base ) . $this->get_template_dir( $instance ) ) . '/'`. On the shortcode path, also validate `design.theme` against the widget's declared styles, or run `update()` on the instance before rendering it. I did not apply or test a patch.

## Affected versions

- Tested and affected: 1.76.0 from wordpress.org.
- I first reproduced this on 1.75.0. `base/inc/shortcode.php` is byte-identical in 1.76.0 and the include in `base/siteorigin-widget.class.php` is unchanged. Earlier versions were not checked.
- Fixed in: no fixed release known.

On 1.75.0 I also saw a Contributor activate a bundled widget through the plugin's `sowb/v1/widgets/forms` REST route. I did not repeat that on 1.76.0, so this report treats widget activation as an administrator setting.

Known entries I compared against: "< 1.74.0 - Contributor+ LFI via 'theme' Parameter" and "< 1.75.0 - Contributor+ Arbitrary File Read via LESS Injection via [siteorigin_widget] Shortcode". This issue still reproduces on 1.76.0.

Tested on a local WordPress lab with test accounts and synthetic data only; no live site was tested.

## Severity

CVSS 3.1 base score **7.5** (High): `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`

- **AV:N** Draft creation and preview are HTTP requests.
- **AC:H** An includable `.php` file must already exist at a path the attacker can name, and the Price Table widget must be active (not the default).
- **PR:L** Contributor (`edit_posts`, no `unfiltered_html`).
- **UI:N** The Contributor triggers it on their own draft.
- **S:U** The included code runs in the WordPress PHP process.
- **C:H / I:H / A:H** Worst case, where a useful PHP file is reachable. The lab only showed a benign echo probe; without a useful file the real effect is lower.

## Credit

thientc (VinSOC)
