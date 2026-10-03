# Changelog

本项目遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## [1.0.1] - 2026-10-03

### Security

- **可信代理网段计算 off-by-one**：通配写法 `203.0.113.*` 原本被算成 `/23`
  （代码写成 `$prefixLen * 8 - 1`），导致相邻的 `203.0.112.*` 也被判定为可信代理。
  由于「信任代理」等于「信任其转发的 `X-Forwarded-For`」，
  攻击者只要位于该相邻网段即可伪造客户端 IP，进而绕过基于 IP 的限流与审计。
  现修正为 `/24`，并对 `203.0.*.5` 这类中途通配直接抛 `InvalidArgumentException`。
- **`data:image/svg+xml` 可作为 XSS 载体**：SVG 是可执行容器，
  放行 `data:image/svg+xml` 等于放行一条绕过路径。现仅允许位图格式。
- **CSP nonce 存在弱随机降级**：`random_bytes()` 失败时曾回退到 `mt_rand()`，
  使 nonce 变得可预测、等同于没有 nonce。现改为直接抛 `RuntimeException`，
  宁可让调用方明确失败也不静默降低安全等级（`RequestGuard` 的令牌生成同样处理）。
- **请求签名可被无效签名「烧掉」nonce**：原实现先登记重放记录再校验签名，
  攻击者可用任意伪造签名提前占用合法 nonce，使真实客户端被拒。
  现改为先验签名、验签通过后才登记重放记录。
- **签名校验可被非十六进制 nonce 绕过**：`hex2bin()` 遇到非法字符返回 `false`，
  而 `false` 会被拼进待签名串，导致签名比对失效。现先做十六进制格式校验。
- **nonce 时间戳不受完整性保护**：原实现只比较 HMAC 段，时间戳可被替换。
  现改为比较完整的「时间戳|签名」。
- **Windows 保留设备名未被拒绝**：`NUL.php`、`con.txt` 等名称在 Windows 上
  不可安全操作，且可用于绕过基于扩展名的上传校验。现在文件名清洗中拒绝。
- **响应头注入面**：`Permissions-Policy` 对带引号的裸值会生成
  `camera=(("self"))` 这类畸形头，使浏览器忽略整条策略。现统一剥除内层引号。
- **HTML 属性值中的 `>` 可导致内容泄漏**：`class="a>b"` 这类值中的 `>`
  会被当作标签结束符，使剩余内容作为纯文本泄漏到输出中。
  现调整标签匹配正则，引号内容优先匹配（`HtmlCleaner` 同样修复）。
- **站点盐文件权限与竞态**：盐文件此前以默认权限写入，且并发进程各自生成不同盐，
  会导致跨进程的 nonce / CSRF 校验互相失效。现以 `'x'` 模式独占创建、权限 0600，
  并在写入失败时回读他人结果。

### Fixed

- `catch (Exception $e)` 在命名空间下未导入 `Exception`，实际捕获的是
  `MornRain\GuardKit\Exception`（不存在），导致 `random_bytes()` 的异常**根本不会被捕获**。
  已在 `RequestGuard` 与 `SecurityHeaders` 中补上 `use Exception;`。
- `setCrossOriginIsolation(false)` 无法关闭先前 `true` 调用留下的
  `Cross-Origin-Opener-Policy`，现改为显式 `unset`。
- `HttpOnly` 之外补充 `SameSite` 语义说明，`sendCookie()` 在
  `headers_sent()` 时静默跳过（行为保持，但已在文档中说明）。

### Added

- `tests/`：111 个用例 / 248 条断言，覆盖 nonce 生命周期与篡改、CSRF、
  签名与重放、令牌桶限流、HTML/SVG/URL/文件名清洗、路径穿越、
  可信代理网段计算与响应头构造。
- `tests/run-tests.php`：零依赖测试运行器。
- `phpunit.xml.dist`、`phpcs.xml.dist`（PSR-12）、`CONTRIBUTING.md`、`SECURITY.md`。

## [1.0.0] - 2026-10-02

### 新增

- `RequestGuard`
  - 请求方法白名单校验（`allowMethods()` / `isMethodAllowed()`）
  - Referer / Origin 来源白名单校验（`isTrustedReferer()`）
  - nonce 生成与校验，WordPress 环境走 `wp_create_nonce()`，
    纯 PHP 环境自动回退到 HMAC-SHA256 + 时间戳 + 盐 的等价实现
  - 双提交 Cookie CSRF 令牌（`csrfToken()` / `verifyCsrf()`）
  - 基于 Transient（无 WP 时回退原子文件）的令牌桶限流（`rateLimit()`）
  - API 请求签名签发与校验，含时间窗口与非重放保护
    （`signRequest()` / `verifyRequestSignature()`）
- `SecurityHeaders`
  - CSP（含 nonce 注入、Report-Only 模式、上报端点）
  - HSTS、X-Frame-Options、Referrer-Policy、Permissions-Policy
  - Cross-Origin-Resource-Policy / Opener-Policy
  - 任意自定义头追加与移除，CRLF 注入防护
  - `toArray()` / `sendHeaders()` / `metaTags()` / `nonceAttribute()` 四种输出方式
- `Sanitizer`
  - HTML 白名单清洗（WordPress 环境走 `wp_kses`，否则使用内置解析器）
  - SVG 防 XSS 清洗（剥离 script / foreignObject / 事件属性 / 外部引用）
  - URL 协议白名单（阻断 `javascript:`、`data:text/html`）
  - 文件名白名单与路径穿越防护
  - 标识符、整数、浮点、邮箱、纯文本清洗
- `IpResolver`
  - 可信代理网段配置（CIDR / 通配 / 单 IP）
  - X-Forwarded-For 从右往左剥离可信代理，防伪造
  - 私有网段判定
- `Compat`：WordPress 函数存在性垫片，保证脱离 WP 也能运行
- `src/functions.php`：14 个 `morn_guard_*` / `morn_sanitize_*` 便捷函数
- `examples/demo.php`：9 个场景的可运行示例

[1.0.0]: https://github.com/mornrain-lin/morn-guard-kit/releases/tag/v1.0.0
