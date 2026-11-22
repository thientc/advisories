# SA-TOKEN-2026-03: Class-level @SaCheckRole / @SaCheckLogin is not applied to handler methods inherited from a base controller

- Product: dromara/Sa-Token (https://github.com/dromara/Sa-Token)
- Reporter: thientc (VinSOC)
- Vendor status: reported 2026-11-17 through GitHub private vulnerability reporting, [GHSA-2jcm-vmf7-g4mx](https://github.com/dromara/Sa-Token/security/advisories/GHSA-2jcm-vmf7-g4mx); in triage, no maintainer reply as of 2026-11-22
- CVE: requested from MITRE on 2026-11-22, pending

## Summary

The docs say a check annotation on a class authorises every method of that class (`use/at-check.md`: "以上注解都可以加在类上，代表为这个类所有方法进行鉴权"). The Javadoc of `@SaCheckRole` and the other annotations says the same. In practice, a handler that the controller inherits from an unannotated base class runs with no check.

`SaAnnotationStrategy` reads class annotations from `method.getDeclaringClass()`, which for an inherited method is the base class, not the controller. Spring still maps that method under the annotated controller's `@RequestMapping` prefix.

## Details

v1.46.0 (`ae58d1cc`):

- `SaInterceptor` passes `((HandlerMethod) handler).getMethod()` to `checkMethodAnnotation`:
  - `sa-token-spring-boot-webmvc-v3v4-common/.../SaInterceptor.java:96-98`;
  - the same code in the Boot 2 starter at `:114-116`.
- `SaAnnotationStrategy.java:103` checks `method.getDeclaringClass()`, then `:139` calls `element.getAnnotation(...)`.
- None of the `@SaCheck*` annotations is `@Inherited`.
- The AOP plugin (`SaAroundAnnotationMethodInterceptor.java:37-38`) goes through the same lookup.

A host cannot fix this through the strategy hooks, because `checkMethodAnnotation` only receives the `Method`, not the bean type.

## PoC

Local lab only: Spring Boot 3.5.16, `sa-token-spring-boot3-starter` 1.46.0 built from the tag, `new SaInterceptor()` on `/**`, user 1 with role `user`.

```java
public abstract class BaseCrud { @GetMapping("/list") public String list() { return "LIST-OK"; } }

@SaCheckRole("admin") @RestController @RequestMapping("/admin/user")
public class UserAdmin extends BaseCrud { @GetMapping("/own") public String own() { return "OWN-OK"; } }
```

Spring maps `{GET [/admin/user/list]} -> UserAdmin#list` (declared in `BaseCrud`).

```
anonymous GET /admin/user/own    -> 403 NotLoginException
user      GET /admin/user/own    -> 403 NotRoleException
anonymous GET /admin/user/list   -> 200 LIST-OK
user      GET /admin/user/list   -> 200 LIST-OK
```

The results are identical with sa-token-spring-aop in place of the interceptor.

Two related cases also skip the check:

- `@SaCheckLogin` on an abstract base class;
- `@SaCheckLogin` on an interface method that carries the `@GetMapping`.

Those match plain Java annotation semantics, so I list them as hardening rather than as part of this report.

## Impact

A shared base controller with generic CRUD handlers is a common pattern. In that setup every inherited endpoint of an `@SaCheckRole("admin")` controller is open to anonymous users. Apps that also protect the prefix with `SaRouter` rules are not affected. I demonstrated a GET that returns a marker; the check is skipped whatever the verb.

Suggested fix: resolve class annotations from the controller type (`HandlerMethod.getBeanType()` / the target class in the AOP advisor) instead of the declaring class. Spring's `AnnotatedElementUtils.findMergedAnnotation` would also cover the abstract-base and interface cases.

## Affected versions

- Tested and affected: 1.46.0 (`ae58d1cc`) on Spring Boot 3.5.16, packages `cn.dev33:sa-token-core` with `sa-token-spring-boot3-starter` and `sa-token-spring-aop`. The Boot 2 starter has the same code in `SaInterceptor`, but I did not run it for this finding.
- Fixed in: no fixed release known.

Tested on a local Spring Boot lab with synthetic accounts and data only; no live deployment was tested. Version tested: 1.46.0.

## Severity

CVSS 3.1 base score **4.8** (Medium): `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

- **AV:N** Plain HTTP.
- **AC:H** It needs a particular host design: a class-level annotation plus handlers inherited from an unannotated base class.
- **PR:N** An anonymous caller reaches the inherited handler.
- **UI:N** No victim action.
- **S:U** The effect stays inside the host application.
- **C:L** Responses of inherited handlers are readable.
- **I:L** Inherited handler actions are callable whatever the verb. On the demonstrated GET read alone this would be C:L/I:N, 3.7.
- **A:N** No availability effect.

## Credit

thientc (VinSOC)
