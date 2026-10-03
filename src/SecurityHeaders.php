<?php
/**
 * HTTP 安全响应头生成器。
 *
 * 负责组装 Content-Security-Policy、Strict-Transport-Security、X-Frame-Options、
 * Referrer-Policy、Permissions-Policy 等响应头，并支持把脚本/样式 nonce
 * 注入 CSP 的 script-src、style-src 指令。
 *
 * 兼容两种输出方式：
 * - sendHeaders()：直接调用 header() 发送（需在输出任何内容前调用）；
 * - toArray()：只返回键值对数组，便于测试、缓存层或 CLI 场景使用。
 *
 * @package MornRain\GuardKit
 */

declare(strict_types=1);

namespace MornRain\GuardKit;

use InvalidArgumentException;
use RuntimeException;
use Exception;

/**
 * 安全响应头类。
 */
class SecurityHeaders
{
    /** @var array<string,string> 待发送的头 */
    protected $headers = [];

    /** @var string 脚本/样式 nonce */
    protected $nonce = '';

    /** @var array<int,string> 需要上报的 CSP 违规来源 */
    protected $reportEndpoints = [];

    /** @var bool 是否已启用 X-Content-Type-Options 等基础头 */
    protected $defaultsEnabled = true;

    /**
     * 生成脚本/样式 nonce（32 位 base64url）。
     *
     * @throws RuntimeException 无法获得密码学随机源。
     */
    public function createNonce(): string
    {
        if ($this->nonce !== '') {
            return $this->nonce;
        }

        // CSP nonce 是安全关键值：这里**不提供** mt_rand 降级。
        // 弱随机会让 nonce 可预测，等于没有 nonce；
        // 宁可明确抛异常，也不要静默降低安全等级。
        if (!function_exists('random_bytes')) {
            throw new RuntimeException('CSP nonce 需要 PHP 7+ 的 random_bytes()，当前环境不可用。');
        }

        try {
            $raw = random_bytes(16);
        } catch (Exception $e) {
            throw new RuntimeException('无法生成密码学安全的 CSP nonce：' . $e->getMessage(), 0, $e);
        }

        $this->nonce = rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');

        return $this->nonce;
    }

    /**
     * 手动指定 nonce（与模板中已输出的值保持一致时使用）。
     */
    public function setNonce(string $nonce): self
    {
        $this->nonce = preg_replace('/[^A-Za-z0-9\-_]/', '', $nonce) ?? '';

        return $this;
    }

    /**
     * 获取当前 nonce，未生成时自动生成。
     */
    public function nonce(): string
    {
        return $this->nonce !== '' ? $this->nonce : $this->createNonce();
    }

    /**
     * 关闭基础安全头（X-Content-Type-Options 等）。
     */
    public function withoutDefaults(): self
    {
        $this->defaultsEnabled = false;

        return $this;
    }

    /**
     * 设置 CSP。
     *
     * @param array<string,mixed> $directives 指令数组，例如 ['default-src' => ["'self'"], 'img-src' => ["'self'", 'data:']]。
     *                                     值为字符串或字符串数组，数组会按序拼接。
     * @param bool                $reportOnly  true 输出 Content-Security-Policy-Report-Only（仅上报不拦截）。
     */
    public function setCsp(array $directives, bool $reportOnly = false): self
    {
        if ($directives === []) {
            throw new InvalidArgumentException('CSP 指令不能为空');
        }

        $key   = $reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
        $parts = [];
        foreach ($directives as $name => $values) {
            $name = strtolower(trim((string) $name));
            if ($name === '' || preg_match('/^[a-z][a-z0-9-]*$/', $name) !== 1) {
                throw new InvalidArgumentException('非法的 CSP 指令名：' . $name);
            }
            $list = is_array($values) ? $values : [$values];
            $list = array_values(array_filter(array_map(static function ($item) {
                return trim((string) $item);
            }, $list), static function (string $item): bool {
                return $item !== '';
            }));
            if ($list === []) {
                continue;
            }
            $parts[] = $name . ' ' . implode(' ', $list);
        }

        if ($parts === []) {
            throw new InvalidArgumentException('CSP 指令全部为空');
        }

        $this->headers[$key] = implode('; ', $parts);

        return $this;
    }

    /**
     * 构造一套适合 WordPress 主题的默认严格 CSP，并把 nonce 注入 script-src / style-src。
     *
     * @param array<int,string> $extraScript 来源白名单。
     * @param array<int,string> $extraStyle  来源白名单。
     * @throws RuntimeException 无法获得密码学随机源（nonce 生成失败）。
     */
    public function withDefaultWordPressCsp(array $extraScript = [], array $extraStyle = []): self
    {
        $nonce = $this->nonce();

        $directives = [
            'default-src'    => ["'self'"],
            'base-uri'       => ["'self'"],
            'object-src'     => ["'none'"],
            'frame-ancestors' => ["'none'"],
            'form-action'    => ["'self'"],
            'script-src'     => array_merge(["'self'", "'nonce-" . $nonce . "'"], $extraScript),
            'style-src'      => array_merge(["'self'", "'nonce-" . $nonce . "'"], $extraStyle),
            'img-src'        => ["'self'", 'data:', 'blob:'],
            'font-src'       => ["'self'", 'data:'],
            'connect-src'    => ["'self'"],
            'media-src'      => ["'self'"],
            'frame-src'      => ["'self'"],
        ];

        if ($this->reportEndpoints !== []) {
            $directives['report-uri'] = array_map(static function (string $uri): string {
                return $uri;
            }, $this->reportEndpoints);
        }

        return $this->setCsp($directives);
    }

    /**
     * 设置 HSTS。
     *
     * @param int  $maxAge     有效期秒数，建议 ≥ 15552000（180 天）。
     * @param bool $subDomains 是否包含子域。
     * @param bool $preload    是否提交预加载。
     */
    public function setHsts(int $maxAge = 15552000, bool $subDomains = true, bool $preload = false): self
    {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('max-age 不得为负');
        }
        $value = 'max-age=' . $maxAge;
        if ($subDomains) {
            $value .= '; includeSubDomains';
        }
        if ($preload) {
            $value .= '; preload';
        }
        $this->headers['Strict-Transport-Security'] = $value;

        return $this;
    }

    /**
     * 设置 X-Frame-Options。
     *
     * @param string $mode DENY / SAMEORIGIN。
     */
    public function setFrameOptions(string $mode = 'DENY'): self
    {
        $mode = strtoupper(trim($mode));
        if (!in_array($mode, ['DENY', 'SAMEORIGIN', 'ALLOW-FROM'], true)) {
            throw new InvalidArgumentException('X-Frame-Options 取值非法：' . $mode);
        }
        $this->headers['X-Frame-Options'] = $mode;

        return $this;
    }

    /**
     * 设置 Referrer-Policy。
     *
     * @param string $policy 取值见 https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy
     */
    public function setReferrerPolicy(string $policy = 'strict-origin-when-cross-origin'): self
    {
        $allowed = [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url',
        ];
        $policy = strtolower(trim($policy));
        if (!in_array($policy, $allowed, true)) {
            throw new InvalidArgumentException('非法的 Referrer-Policy 取值：' . $policy);
        }
        $this->headers['Referrer-Policy'] = $policy;

        return $this;
    }

    /**
     * 设置 Permissions-Policy。
     *
     * @param array<string,string> $features 功能名 => 允许列表，如 ['geolocation' => "(self)", 'camera' => '()']。
     */
    public function setPermissionsPolicy(array $features): self
    {
        $parts = [];
        foreach ($features as $feature => $allowlist) {
            $feature = strtolower(trim((string) $feature));
            if ($feature === '' || preg_match('/^[a-z0-9-]+$/', $feature) !== 1) {
                continue;
            }
            $allow = trim((string) $allowlist);
            if ($allow === '') {
                continue;
            }
            // 已带括号的是完整 allowlist；裸值统一包成 allowlist。
            // 注意裸值内部若含引号，必须剥掉 —— 否则会生成
            // camera=("self") 这种嵌套引号的畸形头，浏览器直接忽略整条策略。
            if (strpos($allow, '(') === 0) {
                $parts[] = $feature . '=' . $allow;
            } else {
                $parts[] = $feature . '=("' . trim(str_replace('"', '', $allow), ' "') . '")';
            }
        }
        if ($parts !== []) {
            $this->headers['Permissions-Policy'] = implode(', ', $parts);
        }

        return $this;
    }

    /**
     * 设置 Cross-Origin 隔离相关头。
     *
     * @param bool $openerPolicy 是否限制 window.opener（COOP）。
     */
    public function setCrossOriginIsolation(bool $openerPolicy = true): self
    {
        $this->headers['X-Content-Type-Options'] = 'nosniff';
        $this->headers['Cross-Origin-Resource-Policy'] = 'same-origin';
        if ($openerPolicy) {
            $this->headers['Cross-Origin-Opener-Policy'] = 'same-origin';
        } else {
            // 必须显式移除：否则先前 true 调用留下的头无法关闭，
            // 重复调用会出现「传 false 却仍然生效」的问题。
            unset($this->headers['Cross-Origin-Opener-Policy']);
        }

        return $this;
    }

    /**
     * 设置 CSP 违规上报端点。
     *
     * @param array<int,string> $endpoints 接收 report-uri 的 URL 列表。
     */
    public function reportTo(array $endpoints): self
    {
        foreach ($endpoints as $endpoint) {
            $endpoint = trim((string) $endpoint);
            if ($endpoint !== '' && $this->isSafeReportUri($endpoint)) {
                $this->reportEndpoints[] = $endpoint;
            }
        }

        return $this;
    }

    /**
     * 追加任意自定义响应头。
     */
    public function setHeader(string $name, string $value): self
    {
        $name = trim($name);
        // 只允许合法 HTTP 头名，避免 CRLF 注入。
        if ($name === '' || preg_match('/^[A-Za-z0-9-]+$/', $name) !== 1) {
            throw new InvalidArgumentException('非法的响应头名称');
        }
        if (preg_match('/[\r\n]/', $value) === 1) {
            throw new InvalidArgumentException('响应头值不得包含换行符');
        }
        $this->headers[$name] = $value;

        return $this;
    }

    /**
     * 设置为「已移除」某个默认头。
     */
    public function removeHeader(string $name): self
    {
        $target = strtolower(trim($name));
        foreach (array_keys($this->headers) as $key) {
            if (strtolower($key) === $target) {
                unset($this->headers[$key]);
            }
        }

        return $this;
    }

    /**
     * 获取全部头（默认值已合并）。
     *
     * @return array<string,string>
     */
    public function toArray(): array
    {
        $headers = [];

        if ($this->defaultsEnabled) {
            $headers['X-Content-Type-Options'] = 'nosniff';
            $headers['X-Frame-Options']        = 'SAMEORIGIN';
            $headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
        }

        // 显式设置覆盖默认值。
        foreach ($this->headers as $name => $value) {
            $headers[$name] = $value;
        }

        return $headers;
    }

    /**
     * 生成 nonce 属性的 HTML 片段。
     *
     * @param string $tag `script` 或 `style`。
     */
    public function nonceAttribute(string $tag = 'script'): string
    {
        $tag = strtolower(trim($tag));
        if (!in_array($tag, ['script', 'style'], true)) {
            throw new InvalidArgumentException('仅支持 script 与 style 标签');
        }

        return 'nonce="' . Compat::attr($this->nonce()) . '"';
    }

    /**
     * 发送响应头。
     *
     * @param bool $replace 是否替换同名已存在头。
     * @return int 成功发送的头数量；输出已开始时返回 0。
     */
    public function sendHeaders(bool $replace = true): int
    {
        if (headers_sent()) {
            return 0;
        }

        $sent = 0;
        foreach ($this->toArray() as $name => $value) {
            header($name . ': ' . $value, $replace);
            $sent++;
        }

        return $sent;
    }

    /**
     * 以 HTML meta 形式输出不适用于 header() 的策略头（用于无法控制响应头的场景）。
     */
    public function metaTags(): string
    {
        $out = [];
        foreach ($this->toArray() as $name => $value) {
            // meta 仅能表达部分策略头，过滤掉仅 header 生效的项。
            if (!in_array($name, ['Content-Security-Policy', 'Referrer-Policy', 'X-Frame-Options', 'X-Content-Type-Options'], true)) {
                continue;
            }
            $out[] = '<meta http-equiv="' . Compat::attr($name) . '" content="' . Compat::attr($value) . '" />';
        }

        return implode("\n", $out);
    }

    /**
     * 校验上报地址是否为安全的同源/相对路径或 https 绝对地址。
     */
    protected function isSafeReportUri(string $uri): bool
    {
        if (strpos($uri, '/') === 0) {
            return true;
        }
        $scheme = strtolower((string) parse_url($uri, PHP_URL_SCHEME));
        $host   = (string) parse_url($uri, PHP_URL_HOST);

        return $scheme === 'https' && $host !== '';
    }
}
