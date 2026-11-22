# MALL-2026-06: Member can overwrite other members' collection documents by id

- Product: macrozheng/mall (https://github.com/macrozheng/mall)
- Reporter: thientc (VinSOC)
- Vendor status: no private reporting channel (GitHub private vulnerability reporting disabled, no SECURITY.md); vendor notified on 2026-11-18 via public GitHub issue https://github.com/macrozheng/mall/issues/1042 (contact request, no technical details), no reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

`POST /member/productCollection/add` in mall-portal keeps the `id` field from the request body and saves the document with Spring Data MongoDB's `save`. If the id belongs to another member's document, that document is overwritten and reassigned to the caller, and the other member loses it. `/member/attention/add` has the same flaw.

## Details

`MemberCollectionServiceImpl.add` (`mall-portal/src/main/java/com/macro/mall/portal/service/impl/MemberCollectionServiceImpl.java:38-41`) sets `memberId`, nickname and icon to the current member but leaves the client-supplied `id` in place. It then calls `productCollectionRepository.save(productCollection)` (`:54`). With an existing `_id`, `save` is an upsert that replaces the stored document, so it now belongs to the caller. The duplicate check before it only looks at the caller's own `(memberId, productId)` pair.

Reads are filtered by `memberId`, so no portal endpoint shows another member's ObjectIds. The ids are predictable, though: they are generated in the portal JVM with a fixed per-process value and a process-wide counter, and both are visible in the ids of the attacker's own entries. Hitting a specific victim needs a guess of when they added an item, which is why I rated attack complexity High.

## PoC

Member B adds a product to their collection and lists it to get the document id. Member A then sends B's id (mall-portal on 8085):

```sh
curl -s -X POST "$PORTAL/member/productCollection/add" --oauth2-bearer "$TOKEN_A" \
  -H 'Content-Type: application/json' -d '{"id":"<B document id>","productId":<other product>}'
curl -s "$PORTAL/member/productCollection/list" --oauth2-bearer "$TOKEN_B"
curl -s "$PORTAL/member/productCollection/list" --oauth2-bearer "$TOKEN_A"
```

The call returned 200. B's list went from 1 entry to 0, and A's list contained a document with B's old id, A's `memberId` and the new product. `/member/attention/add` behaved the same way with a brand-follow document.

## Impact

A member can delete or take over other members' saved-product and brand-follow entries if they know or guess the document id. The data is low value, but writes to other users' records should not be possible at all.

Suggested fix: clear `id` from the request (`productCollection.setId(null)`) before saving, in both `MemberCollectionServiceImpl.add` and `MemberAttentionServiceImpl.add`. With that change on a patched build, B's document is untouched, A gets a new document, and normal add/list/delete still work.

## Affected versions

- Tested and affected: master at commit dcaa93b (`master-dcaa93b`).
- `MemberCollectionServiceImpl.add` is the same in the v1.0.3 tag; I read it but did not run it there.
- Fixed in: no fixed release was known when this report was drafted.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: master-dcaa93b.

## Severity

CVSS 3.1 base score **3.1** (Low): `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`

- **AV:N / PR:L** Any member over HTTP.
- **AC:H** The victim's ObjectId is not disclosed; it has to be predicted from the counter and the victim's timing.
- **UI:N / S:U** No victim interaction; same application.
- **I:L** Low-value collection and follow data of another member is replaced or removed.
- **C:N / A:N** Nothing is read; no outage.

## Credit

thientc (VinSOC)
