<?php
/**
 * 便捷函数包装层。
 *
 * 这些函数把 RequestGuard / SecurityHeaders / Sanitizer / IpResolver
 * 包装成可直接调用的短函数，适合在主题模板与插件中零配置使用。
 * 全部为「惰性单例」：首次调用时创建实例，之后复用。
 *
 * 命名规则统一为 morn_guard_*，避免与其他库冲突。
 *
 * @package MornRain\GuardKit
 */

declare(strict_types=1);

namespace MornRain\GuardKit;

if (!function_exists(__NAMESPACE__ . '\\morn_guard')) {
    /**
     * 获取默认 RequestGuard 实例（惰性创建）。
     *
     * @param string $action   动作名。
     * @param int    $lifetime nonce 有效期。
     */
    function morn_guard(string $action = 'morn_guard', int $lifetime = 43200): RequestGuard
    {
        static $instances = [];
        $key = $action . '|' . $lifetime;
        if (!isset($instances[$key])) {
            $instances[$key] = new RequestGuard($action, $lifetime);
        }

        return $instances[$key];
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_check_nonce')) {
    /**
     * 校验 nonce 字段。
     *
     * @param string $action 动作名。
     */
    function morn_guard_check_nonce(string $action = 'morn_guard'): bool
    {
        return morn_guard($action)->verifyNonce();
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_nonce_field')) {
    /**
     * 输出 nonce 隐藏域 HTML。
     */
    function morn_guard_nonce_field(string $action = 'morn_guard'): string
    {
        return morn_guard($action)->nonceField();
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_csrf_token')) {
    /**
     * 生成 CSRF 令牌。
     */
    function morn_guard_csrf_token(string $action = 'morn_guard'): string
    {
        return morn_guard($action)->csrfToken();
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_check_csrf')) {
    /**
     * 校验 CSRF 令牌。
     */
    function morn_guard_check_csrf(string $action = 'morn_guard'): bool
    {
        return morn_guard($action)->verifyCsrf();
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_method_allowed')) {
    /**
     * 校验当前请求方法。
     *
     * @param array<int,string> $allowedMethods 允许的方法。
     */
    function morn_guard_method_allowed(array $allowedMethods = ['POST'], string $action = 'morn_guard'): bool
    {
        return morn_guard($action)->allowMethods($allowedMethods)->isMethodAllowed();
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_trusted_referer')) {
    /**
     * 校验来源是否在白名单内。
     *
     * @param array<int,string> $allowedHosts 允许的来源主机。
     */
    function morn_guard_trusted_referer(array $allowedHosts = [], string $action = 'morn_guard'): bool
    {
        return morn_guard($action)->isTrustedReferer($allowedHosts);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_rate_limit')) {
    /**
     * 令牌桶限流判断。
     *
     * @param string $key       限流维度标识。
     * @param int    $capacity  桶容量。
     * @param float  $refillRate 每秒补充令牌数。
     */
    function morn_guard_rate_limit(string $key, int $capacity = 20, float $refillRate = 0.5, string $action = 'morn_guard'): bool
    {
        return morn_guard($action)->rateLimit($key, $capacity, $refillRate);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_guard_client_ip')) {
    /**
     * 解析真实客户端 IP。
     *
     * @param array<int,string> $trustedProxies 可信代理网段。
     */
    function morn_guard_client_ip(array $trustedProxies = []): string
    {
        static $resolver = null;
        if ($resolver === null) {
            $resolver = new IpResolver($trustedProxies);
        }

        return $resolver->resolve();
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_sanitize_html')) {
    /**
     * 清洗 HTML。
     */
    function morn_sanitize_html(string $html, bool $keepStyle = false): string
    {
        static $sanitizer = null;
        if ($sanitizer === null) {
            $sanitizer = new Sanitizer();
        }

        return $sanitizer->html($html, $keepStyle);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_sanitize_svg')) {
    /**
     * 清洗 SVG。
     */
    function morn_sanitize_svg(string $svg): string
    {
        static $sanitizer = null;
        if ($sanitizer === null) {
            $sanitizer = new Sanitizer();
        }

        return $sanitizer->svg($svg);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_sanitize_url')) {
    /**
     * 清洗 URL。
     */
    function morn_sanitize_url(string $url): string
    {
        static $sanitizer = null;
        if ($sanitizer === null) {
            $sanitizer = new Sanitizer();
        }

        return $sanitizer->url($url);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_sanitize_filename')) {
    /**
     * 清洗文件名。
     *
     * @param array<int,string> $allowedExtensions 允许的扩展名。
     */
    function morn_sanitize_filename(string $filename, array $allowedExtensions = []): string
    {
        static $sanitizer = null;
        if ($sanitizer === null) {
            $sanitizer = new Sanitizer();
        }

        return $sanitizer->filename($filename, $allowedExtensions);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_safe_path')) {
    /**
     * 路径穿越防护，返回越界时空串。
     */
    function morn_safe_path(string $baseDir, string $path): string
    {
        static $sanitizer = null;
        if ($sanitizer === null) {
            $sanitizer = new Sanitizer();
        }

        return $sanitizer->safePath($baseDir, $path);
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_security_headers')) {
    /**
     * 获取默认 SecurityHeaders 实例。
     */
    function morn_security_headers(): SecurityHeaders
    {
        static $headers = null;
        if ($headers === null) {
            $headers = new SecurityHeaders();
        }

        return $headers;
    }
}

if (!function_exists(__NAMESPACE__ . '\\morn_send_security_headers')) {
    /**
     * 一次性应用并发送推荐的安全响应头。
     *
     * @param bool $withCsp 是否同时发送严格 CSP。
     */
    function morn_send_security_headers(bool $withCsp = true): int
    {
        $headers = new SecurityHeaders();
        $headers->setHsts(15552000, true, false)
            ->setFrameOptions('SAMEORIGIN')
            ->setReferrerPolicy('strict-origin-when-cross-origin')
            ->setPermissionsPolicy([
                'geolocation' => '()',
                'camera'      => '()',
                'microphone' => '()',
                'payment'     => '()',
            ])
            ->setCrossOriginIsolation(false);

        if ($withCsp) {
            $headers->withDefaultWordPressCsp();
        }

        return $headers->sendHeaders(false);
    }
}
