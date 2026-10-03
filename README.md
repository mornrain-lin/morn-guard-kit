# MornRain Guard Kit

WordPress 请求防护与安全响应头工具集。零外部依赖，同时兼容 WordPress 环境与纯 PHP 环境。

[![PHP](https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-406%20passed-success.svg)](tests/)
[![PHPStan](https://img.shields.io/badge/static%20analysis-clean-brightgreen.svg)](CONTRIBUTING.md)

## 简介

主题与插件开发者反复实现同一批安全逻辑：校验表单来源、生成 nonce、限流防刷、
下发 CSP 头、清洗用户提交的 HTML、正确识别 CDN 后的真实 IP。
这些逻辑分散在各项目里，安全性参差不齐。

MornRain Guard Kit 把它们收敛为一个**零依赖、可单测、可在 WordPress 内外运行**的库。
遇到 WordPress 时自动复用 `wp_create_nonce()` / `wp_kses()` 等成熟实现；
不在 WordPress 中时（例如 CLI 工具、静态站点生成器）自动回退到等价的纯 PHP 实现，
因此同一份代码在两种环境都能工作，行为差异仅限实现细节。

## 特性

| 能力 | 说明 |
| --- | --- |
| 双重 nonce 实现 | WordPress 用 `wp_create_nonce()`；纯 PHP 用 HMAC-SHA256 + 站点盐 + 时间戳 |
| CSRF 令牌 | 双提交 Cookie 方案，SameSite=Lax + HttpOnly，派生用 HMAC |
| 令牌桶限流 | 基于 Transient（回退原子文件），支持突发量与持续速率两个维度 |
| API 签名 | HMAC-SHA256 签名 + 时间窗口 + nonce 防重放 |
| 安全响应头 | CSP / HSTS / X-Frame-Options / Referrer-Policy / Permissions-Policy，CSP 支持 nonce 注入与 Report-Only |
| HTML 清洗 | 白名单标签 + 白名单属性，剥离脚本、事件属性、危险协议 |
| SVG 清洗 | 剥离 `<script>`、`<foreignObject>`、事件属性、站外 `url()` 引用，防 SVG XSS |
| 路径穿越防护 | 逐段消解 `.` 与 `..`，确保目标路径留在基准目录内 |
| 可信代理 IP | CIDR / 通配网段配置，XFF 从右往左剥离，客户端无法伪造 |
| 纯 PHP 可跑 | 全部 WordPress 函数均有 `function_exists` 保护，CLI 下可直接运行示例 |

## 安装

```bash
composer require mornrain/morn-guard-kit
```

或手动引入（无 Composer 环境）：

```php
require_once __DIR__ . '/morn-guard-kit/src/Compat.php';
require_once __DIR__ . '/morn-guard-kit/src/RequestGuard.php';
require_once __DIR__ . '/morn-guard-kit/src/SecurityHeaders.php';
require_once __DIR__ . '/morn-guard-kit/src/Sanitizer.php';
require_once __DIR__ . '/morn-guard-kit/src/IpResolver.php';
require_once __DIR__ . '/morn-guard-kit/src/functions.php';
```

## 快速开始

### 表单 nonce

```php
use MornRain\GuardKit\RequestGuard;

$guard = new RequestGuard('contact_submit');
$guard->allowMethods(['POST']);

// 模板中输出隐藏域
echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
echo $guard->nonceField();
echo '<button type="submit">发送</button>';
echo '</form>';

// 处理请求
if (! $guard->isMethodAllowed()) {
    wp_die('非法请求方法', '', ['response' => 405]);
}
if (! $guard->verifyNonce()) {
    wp_die('令牌已过期，请刷新页面重试', '', ['response' => 403]);
}
```

### 限流防刷

```php
$guard = new RequestGuard('contact_submit');
$retryAfter = null;

if (! $guard->rateLimit('contact', 5, 0.1, $retryAfter)) {
    // 桶容量 5，每秒补 0.1 个 → 平均 10 秒一次请求
    wp_die('提交过于频繁，请 ' . $retryAfter . ' 秒后再试', '', ['response' => 429]);
}
```

### 下发安全响应头

```php
use MornRain\GuardKit\SecurityHeaders;

$headers = new SecurityHeaders();
$headers->setHsts(15552000, true)
    ->setFrameOptions('DENY')
    ->setReferrerPolicy('strict-origin-when-cross-origin')
    ->setPermissionsPolicy(['geolocation' => '()', 'camera' => '()'])
    ->withDefaultWordPressCsp();   // 自动注入 nonce

$headers->sendHeaders();

// 模板中的内联脚本/样式使用同一个 nonce
echo '<script ' . $headers->nonceAttribute('script') . '>/* ... */</script>';
echo '<style ' . $headers->nonceAttribute('style') . '>/* ... */</style>';
```

### 清洗用户内容

```php
use MornRain\GuardKit\Sanitizer;

$sanitizer = new Sanitizer();

echo $sanitizer->html($userSubmittedHtml);              // 白名单 HTML
echo $sanitizer->svg($uploadedSvg);                      // 防 XSS 的 SVG
echo $sanitizer->url($input);                            // 阻断 javascript: 与 data:text/html
echo $sanitizer->filename($input, ['jpg', 'png']);       // 文件名白名单
echo $sanitizer->safePath('/var/www/uploads', $input);   // 路径穿越防护，越界返回空串
```

### 解析真实客户端 IP

```php
use MornRain\GuardKit\IpResolver;

$resolver = new IpResolver(['10.0.0.0/8', '172.16.0.0/12', '203.0.113.7']);

// REMOTE_ADDR = 10.0.1.5, XFF = "9.9.9.9, 1.2.3.4, 10.0.1.5" → 返回 1.2.3.4
$ip = $resolver->resolve();
```

### 便捷函数

```php
// 惰性单例，免去实例化
morn_guard_check_nonce('contact_submit');
echo morn_guard_nonce_field('contact_submit');
morn_guard_rate_limit('contact', 5, 0.1);

echo morn_sanitize_html($html);
echo morn_sanitize_url($url);
echo morn_safe_path(WP_CONTENT_DIR, $relative);

morn_send_security_headers(true);   // 一键下发推荐头集合
```

## API 一览表

### `RequestGuard`

| 方法 | 签名 | 说明 |
| --- | --- | --- |
| `__construct` | `(string $action = 'morn_guard', int $lifetime = 43200, string $storageDir = '')` | 动作名隔离 nonce 作用域 |
| `allowMethods` | `(array $methods): self` | 设置允许的 HTTP 方法 |
| `enforceReferer` | `(bool $enabled = true): self` | 开关来源强校验 |
| `isMethodAllowed` | `(?string $method = null): bool` | 校验请求方法 |
| `isTrustedReferer` | `(array $allowedHosts = [], string $allowedHost = ''): bool` | 校验来源白名单 |
| `createNonce` | `(): string` | 生成 nonce |
| `verifyNonce` | `(?string $nonce = null): bool` | 校验 nonce |
| `nonceField` | `(bool $referer = true): string` | 生成隐藏域 HTML |
| `extractNonce` | `(array $source = []): string` | 只取值不校验 |
| `csrfToken` | `(string $cookieName = 'morn_csrf'): string` | 生成 CSRF 令牌 |
| `verifyCsrf` | `(?string $token = null, string $cookieName = 'morn_csrf'): bool` | 校验 CSRF 令牌 |
| `rateLimit` | `(string $key, int $capacity = 20, float $refillRate = 0.5, ?int &$retryAfter = null): bool` | 令牌桶限流 |
| `signRequest` | `(string $secret, string $method, string $path, ?int &$timestamp = null): array` | 签发 API 签名 |
| `verifyRequestSignature` | `(string $secret, string $method, string $path, string $timestamp, string $signature, string $nonce, int $tolerance = 300): bool` | 校验 API 签名 |

### `SecurityHeaders`

| 方法 | 签名 | 说明 |
| --- | --- | --- |
| `createNonce` | `(): string` | 生成 32 位 base64url nonce |
| `setNonce` | `(string $nonce): self` | 指定已有 nonce |
| `nonce` | `(): string` | 读取 nonce |
| `setCsp` | `(array $directives, bool $reportOnly = false): self` | 设置 CSP |
| `withDefaultWordPressCsp` | `(array $extraScript = [], array $extraStyle = []): self` | WP 严格 CSP + nonce 注入 |
| `setHsts` | `(int $maxAge = 15552000, bool $subDomains = true, bool $preload = false): self` | 设置 HSTS |
| `setFrameOptions` | `(string $mode = 'DENY'): self` | 设置 X-Frame-Options |
| `setReferrerPolicy` | `(string $policy = 'strict-origin-when-cross-origin'): self` | 设置 Referrer-Policy |
| `setPermissionsPolicy` | `(array $features): self` | 设置 Permissions-Policy |
| `setCrossOriginIsolation` | `(bool $openerPolicy = true): self` | 设置 Cross-Origin 系列头 |
| `reportTo` | `(array $endpoints): self` | 配置 CSP 上报端点 |
| `setHeader` / `removeHeader` | `(string $name, string $value): self` / `(string $name): self` | 自定义头管理 |
| `toArray` | `(): array` | 取得全部头 |
| `sendHeaders` | `(bool $replace = true): int` | 发送响应头 |
| `metaTags` | `(): string` | 输出 meta 形式策略头 |
| `nonceAttribute` | `(string $tag = 'script'): string` | 生成 nonce 属性片段 |

### `Sanitizer`

| 方法 | 签名 | 说明 |
| --- | --- | --- |
| `allowTags` / `addTags` | `(array $tags): self` | 覆盖 / 追加标签白名单 |
| `allowAttributes` / `addGlobalAttributes` | `(array $map): self` / `(array $attrs): self` | 覆盖 / 追加属性白名单 |
| `html` | `(string $html, bool $keepStyle = false): string` | HTML 白名单清洗 |
| `svg` | `(string $svg): string` | SVG 防 XSS 清洗 |
| `url` | `(string $url): string` | URL 协议白名单 |
| `filename` | `(string $filename, array $allowedExtensions = [], string $fallback = 'file'): string` | 文件名白名单 |
| `safePath` | `(string $baseDir, string $path, bool $allowRelative = false): string` | 路径穿越防护 |
| `identifier` | `(string $identifier): string` | SQL 标识符白名单 |
| `text` | `(string $text, bool $keepNewlines = true): string` | 纯文本清洗 |
| `integer` / `float` | `($value, $min, $max): int / float` | 数值范围裁剪 |
| `email` | `(string $email): string` | 邮箱校验 |

### `IpResolver`

| 方法 | 签名 | 说明 |
| --- | --- | --- |
| `__construct` | `(array $trustedProxies = [])` | 配置可信代理网段 |
| `addTrustedProxy` | `(string $cidr): self` | 追加网段（CIDR / 通配 / 单 IP） |
| `withoutTrustedProxies` | `(): self` | 清空配置，忽略一切代理头 |
| `headerPriority` | `(array $keys): self` | 自定义请求头优先顺序 |
| `resolve` | `(?array $server = null): string` | 解析真实客户端 IP |
| `isTrusted` | `(string $ip): bool` | 是否属于可信代理 |
| `isPrivate` | `(string $ip): bool` | 是否私有 / 保留网段 |

### 便捷函数

| 函数 | 说明 |
| --- | --- |
| `morn_guard()` | 获取惰性单例 `RequestGuard` |
| `morn_guard_nonce_field()` | 输出 nonce 隐藏域 |
| `morn_guard_check_nonce()` | 校验 nonce |
| `morn_guard_csrf_token()` | 生成 CSRF 令牌 |
| `morn_guard_check_csrf()` | 校验 CSRF 令牌 |
| `morn_guard_method_allowed()` | 校验请求方法 |
| `morn_guard_trusted_referer()` | 校验来源白名单 |
| `morn_guard_rate_limit()` | 令牌桶限流 |
| `morn_guard_client_ip()` | 解析真实客户端 IP |
| `morn_sanitize_html()` | HTML 清洗 |
| `morn_sanitize_svg()` | SVG 清洗 |
| `morn_sanitize_url()` | URL 清洗 |
| `morn_sanitize_filename()` | 文件名清洗 |
| `morn_safe_path()` | 路径穿越防护 |
| `morn_security_headers()` | 获取 `SecurityHeaders` 单例 |
| `morn_send_security_headers()` | 一键下发安全头 |

## Hook / 扩展点

本库**不注册任何 WordPress Hook**，也不会污染全局状态，因此不会与其他插件冲突。
所有扩展都通过「子类覆盖」实现：

```php
// 自定义 nonce 生命周期与存储目录
final class MyGuard extends \MornRain\GuardKit\RequestGuard
{
    public function __construct()
    {
        parent::__construct('my_action', 3600, WP_CONTENT_DIR . '/guard');
    }
}

// 自定义清洗白名单
final class MySanitizer extends \MornRain\GuardKit\Sanitizer
{
    public function __construct()
    {
        $this->allowTags(['p', 'a', 'img', 'table', 'figure', 'video']);
        $this->allowAttributes([
            'a'   => ['href', 'title', 'rel', 'target'],
            'img' => ['src', 'alt', 'width', 'height', 'loading'],
            'video' => ['src', 'controls', 'poster'],
        ]);
    }
}
```

在 WordPress 中若需全局生效，可在 `functions.php` 或主题的 `after_setup_theme` 阶段
输出安全头（注意须在任何输出之前）：

```php
add_action('send_headers', function (): void {
    (new \MornRain\GuardKit\SecurityHeaders())
        ->setHsts(15552000, true)
        ->setFrameOptions('SAMEORIGIN')
        ->withDefaultWordPressCsp()
        ->sendHeaders();
});
```

## FAQ

**Q：脱离 WordPress 也能用吗？**
可以。所有类都不继承、不依赖任何 WordPress 类型；`wp_create_nonce()`、`wp_kses()`、
`esc_attr()` 等调用都做了 `function_exists` 保护，不存在时使用内置等价实现。
`examples/demo.php` 可直接在 CLI 下运行验证。

**Q：nonce 回退实现和 WordPress nonce 一样安全吗？**
安全级别相当：都是「HMAC(动作 + 用户 + 时间戳, 站点盐) + 时间窗校验 + 恒定时间比较」。
差别在于盐的来源——WordPress 用 `NONCE_SALT` 常量，回退实现优先读 `LOGGED_IN_SALT` /
`NONCE_SALT`，都没有时会在临时目录生成一次随机盐并持久化。**一旦站点定义了
`NONCE_SALT`（WordPress 安装向导默认会生成），回退实现与 WordPress 行为完全一致。**

**Q：`rateLimit()` 为什么用 Transient？**
因为 Transient 是 WordPress 唯一同时具备「自动过期」和「跨请求共享」的原生 API，
且能自动跟随对象缓存（Redis / Memcached）扩展。纯 PHP 环境回退到带原子 `rename`
写入的文件存储，同样具备过期语义。

**Q：`capacity` 和 `refillRate` 怎么选？**
`capacity` 决定突发容忍量（用户一次提交多个表单不会被拦），
`refillRate` 决定长期速率（`0.1` = 平均 10 秒一次）。经验值：
表单防刷用 `capacity=5, refillRate=0.1`；API 接口用 `capacity=30, refillRate=2`。

**Q：X-Forwarded-For 可以被客户端伪造吗？**
单独使用时可以——任何人都能设置 `X-Forwarded-For: 1.2.3.4`。
本库的做法是：只有当 `REMOTE_ADDR` 落在你显式配置的可信代理网段内，
才去读代理头；并且从 XFF 链的**最右侧**开始向左剥离可信代理，
第一个不可信地址才是客户端 IP。未配置可信代理时，所有代理头一律忽略。
**不配置可信代理 = 最安全的默认行为。**

**Q：Sanitizer 会删除我所有的 HTML 吗？**
不会。默认白名单保留了 60 余个常用排版标签（表格、figure、code、time 等）。
注意 `style` 属性默认被丢弃，传入 `$keepStyle = true` 可保留经过属性级白名单过滤的样式。

**Q：能不能只取某一个类的功能，不装 Composer？**
可以。每个类都是零依赖单文件，直接 `require_once` 对应文件即可，
见「安装」一节的第二种方式。

**Q：`safePath()` 为什么不调用 `realpath()`？**
因为要校验的目标文件经常尚不存在（上传前的路径校验）。
本库改为逐段消解 `.` 与 `..` 后做前缀比对，效果等价且不依赖文件系统状态。

**Q：CSP 会不会把合法的内联脚本全部拦掉？**
`withDefaultWordPressCsp()` 会自动生成 nonce 并注入 `script-src` / `style-src`。
你只需用 `nonceAttribute('script')` 把同一个 nonce 输出到所有内联标签上。
若站点存在必须保留的无 nonce 内联脚本，可改用 `setCsp()` 显式配置
并配合 `setCsp($directives, true)` 的 Report-Only 模式先观察一段时间再切强制。

## 目录说明

```
morn-guard-kit/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── composer.json
├── .gitignore
├── .gitattributes
├── src/
│   ├── Compat.php            # WordPress 函数存在性垫片
│   ├── RequestGuard.php      # 方法/来源校验、nonce、CSRF、限流、API 签名
│   ├── SecurityHeaders.php   # CSP / HSTS / X-Frame-Options 等响应头
│   ├── Sanitizer.php         # HTML / SVG / URL / 文件名 / 路径清洗
│   ├── IpResolver.php        # 可信代理链 IP 解析
│   └── functions.php         # morn_guard_* 便捷函数
├── tests/                   # 单元测试 + 零依赖运行器
│   ├── run-tests.php        # 零依赖测试运行器
│   ├── TestCase.php         # 断言（兼容 PHPUnit / 独立运行）
│   └── bootstrap.php        # PHPUnit 引导
├── phpunit.xml.dist         # PHPUnit 配置
├── phpcs.xml.dist           # PSR-12 代码风格
├── CONTRIBUTING.md          # 贡献指南
├── SECURITY.md              # 安全策略
└── examples/
    └── demo.php              # 9 个场景可运行示例
```

## 测试

本库提供两条等价的测试路径，用同一份用例：

```bash
# 零依赖方式，不需要 composer install
php tests/run-tests.php

# 只跑名称含某关键字的用例
php tests/run-tests.php robots

# 装了 PHPUnit 时
composer test          # 走 vendor/bin/phpunit
composer lint          # php -l 逐文件语法检查
composer lint:style    # PSR-12 代码风格
```

用例覆盖正常路径、边界情况（空值 / 零与负数 / 超长输入 / 多字节与 emoji）
与安全路径（注入、XSS、路径穿越、令牌篡改、重放）。
修bug 时请一并补上能复现该问题的断言。

参与贡献请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)；
发现安全问题请**不要**公开提issue，参见 [SECURITY.md](SECURITY.md)。

## License

MIT License — Copyright (c) 2026 MornRain

详见 [LICENSE](LICENSE)。

本库不收集、不传输任何数据；限流与 nonce 状态仅存储在本地站点自身的
Transient、对象缓存或临时目录中。
