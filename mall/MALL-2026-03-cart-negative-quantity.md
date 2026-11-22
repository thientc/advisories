# MALL-2026-03: Negative cart quantity lowers the order total and inflates stock

- Product: macrozheng/mall (https://github.com/macrozheng/mall)
- Reporter: thientc (VinSOC)
- Vendor status: no private reporting channel (GitHub private vulnerability reporting disabled, no SECURITY.md); vendor notified on 2026-11-18 via public GitHub issue https://github.com/macrozheng/mall/issues/1042 (contact request, no technical details), no reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

The mall-portal cart accepts negative quantities. A logged-in member can add an item with `"quantity":-1` (or set an existing line to a negative number through `/cart/update/quantity`), and the order total is computed as `price * quantity` over every line. Mixing one real item with one negative line lowers the amount to pay, down to 0.00 or below, and paying a negative order pushes stock up instead of down.

## Details

`POST /cart/add` (`mall-portal/src/main/java/com/macro/mall/portal/controller/OmsCartItemController.java:33`) and `GET /cart/update/quantity` (`OmsCartItemController.java:58-66`) take `quantity` straight from the request. `OmsCartItemServiceImpl.add` stores it as is (`OmsCartItemServiceImpl.java:48`, and `:51` adds it to an existing row); `updateQuantity` (`:95-101`) does the same. There is no lower bound anywhere on the path.

When the order is generated in `OmsPortalOrderServiceImpl`:

- `hasStock` (`OmsPortalOrderServiceImpl.java:751`) checks `realStock >= quantity`, which is always true for a negative quantity.
- `calcTotalAmount` (`:726`) sums `price * quantity`, so a negative line subtracts its value from the total, and `pay_amount` follows.
- `lockStock` (`:737`) adds the negative quantity to `lock_stock`, and marking the order paid later applies it to `stock`.

The database columns are signed, so nothing rejects the values at that layer either. Promotion type 1 products reset the price but not the quantity, so they can be used as the negative line too.

## PoC

As any member (`$TOKEN` from `/sso/login`), against mall-portal on its default port 8085. `<A>` is a normal product SKU, `<B>` a second one:

```sh
PORTAL=http://<mall-portal-host>:8085
curl -s -X POST "$PORTAL/cart/add" --oauth2-bearer "$TOKEN" -H 'Content-Type: application/json' \
  -d '{"productId":<A>,"productSkuId":<A sku>,"quantity":2}'
curl -s -X POST "$PORTAL/cart/add" --oauth2-bearer "$TOKEN" -H 'Content-Type: application/json' \
  -d '{"productId":<B>,"productSkuId":<B sku>,"quantity":-1}'
curl -s "$PORTAL/cart/list" --oauth2-bearer "$TOKEN"            # note both cart ids
curl -s -X POST "$PORTAL/order/generateOrder" --oauth2-bearer "$TOKEN" -H 'Content-Type: application/json' \
  -d '{"memberReceiveAddressId":<address id>,"payType":1,"useIntegration":0,"cartIds":[<id1>,<id2>]}'
```

With both products priced 100.00, I got:

- 2 × A plus −1 × B: order created with `pay_amount` 100.00 instead of 200.00; the order items show quantities 2 and −1.
- 1 × A plus B set to −1 through `GET /cart/update/quantity?id=<id>&quantity=-1`: `total_amount` 0.00 and `pay_amount` 0.00.
- B alone at −3: `pay_amount` −300.00. B's `lock_stock` went negative, and after the order was marked paid B's `stock` went from 100 to 103.

## Impact

Any registered member can choose what they pay for real goods, including nothing, as long as they add a negative line next to what they actually want. Orders with a total of zero or less, and stock counts that rise when such an order is paid, also corrupt the shop's accounting and inventory. In my lab the paid state for the negative order was set through the member `paySuccess` endpoint; with a real payment provider the discounted (positive) mixed order goes through the normal payment flow.

Suggested fix: reject `quantity < 1` in `/cart/add` and `/cart/update/quantity` (and ideally again when the order is generated). With that check on a patched build, both calls are refused and normal orders with positive quantities still work.

## Affected versions

- Tested and affected: master at commit dcaa93b (`master-dcaa93b`).
- The same cart code is in the v1.0.3 tag; I read it but did not run it there.
- Fixed in: no fixed release was known when this report was drafted.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: master-dcaa93b.

## Severity

CVSS 3.1 base score **6.5** (Medium): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`

- **AV:N / AC:L** One HTTP request per cart line, no special conditions.
- **PR:L** Any member account; registration is open.
- **UI:N / S:U** No victim; the effect stays in the shop.
- **C:N** Nothing is read.
- **I:H** The member sets the order amount, down to zero or below, and inflates stock.
- **A:N** No outage.

## Credit

thientc (VinSOC)
