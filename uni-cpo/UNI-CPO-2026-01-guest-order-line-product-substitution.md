# UNI-CPO-2026-01: Guest can swap the product on an order line for another product while paying the cheap product's price

- Product: Product Options and Price Calculation Formulas for WooCommerce – Uni CPO (https://wordpress.org/plugins/uni-woo-custom-product-options/); source published on the wordpress.org plugin SVN, no official GitHub repository known to me
- Affected: 4.9.71, the latest release on wordpress.org when checked on 2026-11-18
- CVSS 3.1: 8.2 (High) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`
- Reporter: thientc (VinSOC)
- Vendor status: not reported to the vendor as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

For a product with Uni CPO options turned on, `uni_cpo_add_cart_item_data()` copies the whole add-to-cart POST body into the cart item, and at checkout `uni_cpo_checkout_create_order_line_item()` writes every key of that copy onto the order line as `_<key>` meta. An extra `product_id` field in the add-to-cart request therefore becomes the line's `_product_id`. In my lab a guest put a 5.00 options-enabled product in the cart with `product_id=<500.00 product>`, checked out for 5.00, and the order line pointed at the 500.00 downloadable product. After the order was marked paid, the guest could download that product's file.

## Details

References are to `includes/uni-cpo-core-functions.php` in 4.9.71.

1. `uni_cpo_add_cart_item_data()` is hooked on `woocommerce_add_cart_item_data` (line 1301). On a classic add-to-cart POST it takes `$form_data = wc_clean( $_POST )` (line 1390) and, for a product with `cpo_enable` on, stores the whole array:

```php
$cart_item_data['_cpo_data'] = ( isset( $form_data['cpo_data'] ) ? $form_data['cpo_data'] : $form_data );
```

(line 1403). The cleanup loop at lines 1424-1432 only unsets keys from `$form_data` and the top level of `$cart_item_data`, so `_cpo_data` keeps every POST key, `product_id` included. `uni_cpo_validate_cart_item_options()` checks the defined option slugs and ignores unknown keys.

2. `uni_cpo_checkout_create_order_line_item()` runs on `woocommerce_checkout_create_order_line_item` (line 1334):

```php
foreach ( $form_data as $name => $value ) {
    $item->add_meta_data( '_' . $name, $value );
}
```

(line 1812). WooCommerce treats the meta key `_product_id` as the item's product ID, and this hook runs after WooCommerce has set the line's real product and totals, so the plugin's value replaces the product while the line keeps the cheap product's price.

Preconditions: at least one simple product with the plugin's options turned on (`_cpo_enable = on`; no options need to be defined), and the target product's ID. Guest checkout makes it unauthenticated; with guest checkout off any customer account works the same way, from the code.

## PoC

Setup: WordPress 7.1.4, WooCommerce 11.3.0, Uni CPO 4.9.71, PHP 8.3. Guest checkout on, Cash on delivery enabled, taxes off.

- Product 10, "Cheap CPO A": simple, virtual, 5.00, `_cpo_enable = on`, no options defined.
- Product 13, "Premium X": simple, virtual, downloadable, 500.00, one synthetic downloadable file.

1. In a fresh session with no login cookie, open product 10 and send the normal add-to-cart POST with one extra field:

```http
POST /?p=10 HTTP/1.1
Host: <host>
Content-Type: application/x-www-form-urlencoded
Cookie: <guest session cookies>

add-to-cart=10&quantity=1&product_id=13
```

WooCommerce adds the item during `wp_loaded`, so this response came back as a 404 in my lab, but the cart now held "Cheap CPO A" at 5.00.

2. Check out through the Store API with the `Nonce` header from `GET /wp-json/wc/store/v1/cart`:

```http
POST /wp-json/wc/store/v1/checkout HTTP/1.1
Host: <host>
Content-Type: application/json
Nonce: <store api nonce>
Cookie: <guest session cookies>

{"billing_address":{"first_name":"Test","last_name":"Guest","address_1":"1 Example St","city":"Example","state":"CA","postcode":"90001","country":"US","email":"<guest email>","phone":"5550100"},"shipping_address":{"first_name":"Test","last_name":"Guest","address_1":"1 Example St","city":"Example","state":"CA","postcode":"90001","country":"US"},"payment_method":"cod","payment_data":[]}
```

3. The new order:

```
status: on-hold   total: 5.00   payment_method: cod
line item: "Cheap CPO A"
item meta: _product_id=13 | _variation_id=0 | _qty=1 | _line_subtotal=5 | _line_total=5
```

The line is still named after product 10, but `_product_id` is 13. The control orders went to `processing` while the attack orders went to `on-hold`; I did not dig into why, but it is consistent with WooCommerce now seeing a downloadable product on the line.

4. Standing in for the shop marking the 5.00 cash payment as received, I set the order to Processing (with wp-cli, `update_status`). WooCommerce then granted a download permission for product 13 to the guest's email. The guest's order-received page listed one download link, and following it returned HTTP 200 with the synthetic file body `lab synthetic premium file X-PAYLOAD-4971`.

Control: the same flow without `product_id=13` produced an order in `processing` with `_product_id=10`, total 5.00, no download permission and no link. I ran the attack twice and the control twice, with orders and permissions reset and a fresh guest session each time; the results matched.

## Impact

A guest can place an order whose line item is a product of their choosing while the order carries the price of a cheap options-enabled product. In the lab a 5.00 order became an order for a 500.00 downloadable product, and once the order was marked paid the guest received that product's protected file. Everything was synthetic.

With cash on delivery the download only appears after the shop marks the order paid. The order shows "Cheap CPO A" by name, so a shop processing a 5.00 payment for it has little reason to look closer, but the `on-hold` status is a visible difference. I did not test a gateway that completes orders automatically on 4.9.71, nor substituting a private product, the `variation_id` key, or the Store API add-to-cart route.

## Suggested fix

Build `_cpo_data` only from the product's own option slugs instead of the raw POST array, and in `uni_cpo_checkout_create_order_line_item()` never pass WooCommerce's internal item keys (`product_id`, `variation_id`, `qty`, `line_total` and the rest) to `add_meta_data()`. I did not test a patch.

## Affected versions

- Tested and affected: 4.9.71 (wordpress.org archive, SHA-256 5f44ac59dd42a741c0b114da2ac5bdd6cc666c82b92daee09935b9932db20dd9).
- I first reproduced the same behaviour on 4.9.69; the code path is unchanged in 4.9.71. Earlier versions were not checked.
- Fixed in: no fixed release known.

Tested on a local WordPress lab with test accounts and synthetic data only; no live store was tested.

## Severity

CVSS 3.1 base score **8.2** (High): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`

- **AV:N** Add-to-cart and Store API checkout over HTTP.
- **AC:L** One extra POST field on a normal add-to-cart.
- **PR:N** Anonymous guest session.
- **UI:N** No one has to be tricked. The step that releases the download is the shop marking a 5.00 order paid, which is normal fulfilment. If a reviewer counts that step as user interaction, UI:R gives 7.1.
- **S:U** Stays within the store.
- **C:L** The guest obtained the substituted product's protected download.
- **I:H** The product and entitlement on the order line are attacker-chosen while the price is another product's. Reading it as affecting only the attacker's own order, I:L gives 6.5.
- **A:N** None observed.

## Credit

thientc (VinSOC)
