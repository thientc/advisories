# MALL-2026-02: Client-supplied cart price becomes the order and payment amount

- Product: macrozheng/mall (https://github.com/macrozheng/mall)
- Reporter: thientc (VinSOC)
- Vendor status: no private reporting channel (GitHub private vulnerability reporting disabled, no SECURITY.md); vendor notified on 2026-11-18 via public GitHub issue https://github.com/macrozheng/mall/issues/1042 (contact request, no technical details), no reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`POST /cart/add` in mall-portal stores the `price` sent by the client, and that price becomes the order item price and the order's `pay_amount`. A member can buy most products for any price they choose, such as 0.01. Since commit dcaa93b, the Alipay payment amount is read from `pay_amount`, so the payment request carries the attacker's price as well.

## Details

The controller binds the whole `OmsCartItem` from the request body, `price` included (`mall-portal/src/main/java/com/macro/mall/portal/controller/OmsCartItemController.java:33`). `OmsCartItemServiceImpl.add` inserts it unchanged (`OmsCartItemServiceImpl.java:48`).

When the order is built, `OmsPromotionServiceImpl` only replaces the price for promotion type 1 (`OmsPromotionServiceImpl.java:51`). For every other type, `handleNoReduce` (`:162`) and the ladder/full-reduction branches (`:65`, `:88`) copy the cart item and keep its price. `OmsPortalOrderServiceImpl` then sets `orderItem.setProductPrice(cartPromotionItem.getPrice())` (`OmsPortalOrderServiceImpl.java:112`) and computes `pay_amount` from those items (`:186`). `AlipayServiceImpl.pay` sends `total_amount = order.getPayAmount()` (`AlipayServiceImpl.java:63-65`).

In the stock `mall.sql` seed, 36 of 38 products (28 of the 30 published ones) are not promotion type 1, so the client price survives for almost the whole catalogue.

This was raised before as #869 and closed. I'm reporting it again because the effect now reaches the stored order and, after dcaa93b, the payment amount. The PoC below shows it at the order level.

## PoC

As any member (`$TOKEN` from `/sso/login`), mall-portal on port 8085, with a product whose `promotion_type` is not 1 and whose list price is 100.00:

```sh
PORTAL=http://<mall-portal-host>:8085
curl -s -X POST "$PORTAL/cart/add" --oauth2-bearer "$TOKEN" -H 'Content-Type: application/json' \
  -d '{"productId":<id>,"productSkuId":<sku id>,"quantity":1,"price":0.01}'
curl -s "$PORTAL/cart/list" --oauth2-bearer "$TOKEN"            # cart line shows price 0.01
curl -s -X POST "$PORTAL/order/generateOrder" --oauth2-bearer "$TOKEN" -H 'Content-Type: application/json' \
  -d '{"memberReceiveAddressId":<address id>,"payType":1,"useIntegration":0,"cartIds":[<cart id>]}'
```

The new order had `total_amount` 0.01 and `pay_amount` 0.01, and its order item had `product_price` 0.01. The catalogue price was 100.00. As a control, the same request for a promotion type 1 product sent with `"price":0.01` produced the correct price (200.00 list, 150.00 to pay).

I could not render the Alipay form in my lab because it has no real Alipay key; the SDK fails at signing, after the order lookup. The 0.01 Alipay amount is taken from the source line above plus the stored `pay_amount`, not from a captured form.

## Impact

Any registered member can place orders for nearly any product at a price they pick, and the payment flow asks them to pay only that amount. A shop that fulfils paid orders without comparing the paid amount with the catalogue price would ship goods for close to nothing.

Suggested fix: ignore the client's `price` in `/cart/add` (copy it from the SKU or product on the server) and recompute item prices from the catalogue when generating the order. With that change on a patched build, the 0.01 request produces a 100.00 order, and normal orders are unchanged.

## Affected versions

- Tested and affected: master at commit dcaa93b (`master-dcaa93b`).
- I also reproduced it at the order level on the v1.0.3 tag in an earlier lab.
- Fixed in: no fixed release was known when this report was drafted.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: master-dcaa93b.

## Severity

CVSS 3.1 base score **6.5** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`

- **AV:N / AC:L** One cart request with a chosen price.
- **PR:L** Any member account; registration is open.
- **UI:N / S:U** No victim; the effect stays in the shop.
- **C:N** Nothing is read.
- **I:H** The member sets the price of the order and of the payment request.
- **A:N** No outage.

## Credit

thientc (VinSOC)
