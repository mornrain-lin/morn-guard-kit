<?php
/**
 * 安全响应头测试。
 *
 * @package MornRain\GuardKit\Tests
 */

declare(strict_types=1);

namespace MornRain\GuardKit\Tests;

use InvalidArgumentException;
use MornRain\GuardKit\SecurityHeaders;

/**
 * SecurityHeaders 测试。
 */
class SecurityHeadersTest extends TestCase
{
    /** @var SecurityHeaders */
    private $h;

    protected function setUp(): void
    {
        $this->h = new SecurityHeaders();
    }

    /* ---------- 默认头 ---------- */

    public function testDefaultHeadersPresent(): void
    {
        $headers = $this->h->toArray();

        self::assertArrayHasKey('X-Content-Type-Options', $headers);
        self::assertArrayHasKey('X-Frame-Options', $headers);
        self::assertArrayHasKey('Referrer-Policy', $headers);
        self::assertSame('nosniff', $headers['X-Content-Type-Options']);
    }

    public function testWithoutDefaultsRemovesBaseHeaders(): void
    {
        $headers = $this->h->withoutDefaults()->toArray();

        self::assertArrayNotHasKey('X-Frame-Options', $headers);
    }

    public function testExplicitValueOverridesDefault(): void
    {
        $headers = $this->h->setFrameOptions('DENY')->toArray();
        self::assertSame('DENY', $headers['X-Frame-Options'], '显式设置应覆盖默认值');
    }

    /* ---------- nonce ---------- */

    public function testNonceIsStableWithinInstance(): void
    {
        $nonce = $this->h->createNonce();

        self::assertSame($nonce, $this->h->createNonce());
        self::assertSame($nonce, $this->h->nonce());
    }

    public function testNonceFormatAndUniqueness(): void
    {
        $a = (new SecurityHeaders())->createNonce();
        $b = (new SecurityHeaders())->createNonce();

        self::assertSame(22, strlen($a), '16 字节 base64url 应为 22 字符');
        self::assertTrue((bool) preg_match('/^[A-Za-z0-9_-]+$/', $a), 'nonce 只含 base64url 字符');
        self::assertNotSame($a, $b, '不同实例的 nonce 必须不同');
    }

    public function testSetNonceIsSanitized(): void
    {
        $this->h->setNonce('abc"><script>123');
        $nonce = $this->h->nonce();

        self::assertSame('abcscript123', $nonce, '非法字符必须被剔除');
    }

    public function testNonceAttributeEscapesValue(): void
    {
        $this->h->setNonce('"><img src=x onerror=alert(1)>');
        $attr = $this->h->nonceAttribute('script');

        self::assertStringContains('nonce="', $attr);
        self::assertStringNotContains('"', substr($attr, 7, -1), '属性值内的引号必须被转义');
    }

    public function testNonceAttributeRejectsUnknownTag(): void
    {
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->nonceAttribute('div');
        });
    }

    /* ---------- CSP ---------- */

    public function testSetCspBuildsDirectives(): void
    {
        $headers = $this->h->setCsp([
            'default-src' => ["'self'"],
            'img-src'     => ["'self'", 'data:'],
        ])->toArray();

        self::assertArrayHasKey('Content-Security-Policy', $headers);
        self::assertStringContains("default-src 'self'", $headers['Content-Security-Policy']);
        self::assertStringContains("img-src 'self' data:", $headers['Content-Security-Policy']);
    }

    public function testSetCspRejectsInvalidInput(): void
    {
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->setCsp([]);
        });
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->setCsp(['bad directive' => ['x']]);
        });
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->setCsp(['default-src' => []]);
        }, '所有指令值为空时应报错');
    }

    public function testCspReportOnlyUsesDifferentHeader(): void
    {
        $headers = $this->h->setCsp(['default-src' => ["'self'"]], true)->toArray();

        self::assertArrayHasKey('Content-Security-Policy-Report-Only', $headers);
        self::assertArrayNotHasKey('Content-Security-Policy', $headers);
    }

    public function testDefaultWordPressCspInjectsNonce(): void
    {
        $nonce   = $this->h->nonce();
        $headers = $this->h->withDefaultWordPressCsp()->toArray();
        $csp     = $headers['Content-Security-Policy'];

        self::assertStringContains("'nonce-{$nonce}'", $csp);
        self::assertStringContains("object-src 'none'", $csp);
        self::assertStringContains("base-uri 'self'", $csp);
        self::assertStringContains("frame-ancestors 'none'", $csp);
    }

    public function testDefaultCspAcceptsExtraSources(): void
    {
        $headers = $this->h->withDefaultWordPressCsp(['https://cdn.example.com'])->toArray();
        self::assertStringContains('https://cdn.example.com', $headers['Content-Security-Policy']);
    }

    /* ---------- HSTS / Frame / Referrer ---------- */

    public function testHsts(): void
    {
        $headers = $this->h->setHsts(31536000, true, true)->toArray();
        $hsts    = $headers['Strict-Transport-Security'];

        self::assertStringContains('max-age=31536000', $hsts);
        self::assertStringContains('includeSubDomains', $hsts);
        self::assertStringContains('preload', $hsts);
    }

    public function testHstsRejectsNegativeMaxAge(): void
    {
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->setHsts(-1);
        });
    }

    public function testFrameOptionsRejectsUnknownMode(): void
    {
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->setFrameOptions('INVALID');
        });
    }

    public function testReferrerPolicyRejectsUnknownValue(): void
    {
        self::assertThrows(InvalidArgumentException::class, function (): void {
            $this->h->setReferrerPolicy('whatever');
        });
    }

    public function testReferrerPolicyAcceptsValidValue(): void
    {
        $headers = $this->h->setReferrerPolicy('no-referrer')->toArray();
        self::assertSame('no-referrer', $headers['Referrer-Policy']);
    }

    /* ---------- 自定义头 ---------- */

    public function testSetHeaderRejectsCrlfInjection(): void
    {
        $headers = $this->h;

        // 头部名非法
        self::assertThrows(InvalidArgumentException::class, static function () use ($headers): void {
            $headers->setHeader('X-Bad Header', 'v');
        });
        // 值里的换行可用于响应头注入 / 拆分响应
        self::assertThrows(InvalidArgumentException::class, static function () use ($headers): void {
            $headers->setHeader('X-Test', "value\r\nSet-Cookie: admin=1");
        });
        self::assertThrows(InvalidArgumentException::class, static function () use ($headers): void {
            $headers->setHeader('X-Test', "value\nInjected: 1");
        });
    }

    public function testRemoveHeaderIsCaseInsensitive(): void
    {
        $headers = $this->h->setHeader('X-Custom', 'v')->removeHeader('x-custom')->toArray();
        self::assertArrayNotHasKey('X-Custom', $headers);
    }

    /* ---------- Permissions-Policy ---------- */

    public function testPermissionsPolicyFormatting(): void
    {
        $headers = $this->h->setPermissionsPolicy([
            'geolocation' => '()',
            'camera'      => 'self',
            ''            => 'x',
            'bad name'    => 'y',
        ])->toArray();

        $policy = $headers['Permissions-Policy'];
        // 语法要求 feature=(allowlist)，引号是规范的一部分
        self::assertStringContains('geolocation=()', $policy);
        self::assertStringContains('camera=("self")', $policy, '裸值应被包成带引号的 allowlist');
        self::assertStringNotContains('bad name', $policy, '非法特性名应被剔除');
        self::assertStringNotContains('("", )', $policy);
    }

    public function testPermissionsPolicyDoesNotNestQuotes(): void
    {
        $headers = $this->h->setPermissionsPolicy(['camera' => '"self"'])->toArray();
        $policy  = $headers['Permissions-Policy'];

        // 输入自带引号时不能生成 camera=(("self")) 这类畸形值
        self::assertSame('camera=("self")', $policy);
    }

    /* ---------- meta 输出 ---------- */

    public function testMetaTagsEscapesValues(): void
    {
        $this->h->setHeader('Referrer-Policy', 'no-referrer');
        $meta = $this->h->metaTags();

        self::assertStringContains('<meta http-equiv=', $meta);
        self::assertStringContains('no-referrer', $meta);
        // 标签结构必须完整
        self::assertSame(substr_count($meta, '<meta'), substr_count($meta, '/>'));
    }

    public function testMetaTagsExcludeHeaderOnlyDirectives(): void
    {
        $meta = $this->h->setHsts(100)->toArray() ? $this->h->metaTags() : '';
        self::assertStringNotContains('Strict-Transport-Security', $meta);
    }

    /* ---------- 上报端点 ---------- */

    public function testReportToAcceptsSafeUrisOnly(): void
    {
        $headers = $this->h->reportTo([
            '/csp-report',              // 相对路径：允许
            'https://a.example/r',      // https：允许
            'http://insecure.example', // http：拒绝
            'javascript:alert(1)',     // 拒绝
        ])->withDefaultWordPressCsp()->toArray();

        $csp = $headers['Content-Security-Policy'];
        self::assertStringContains('report-uri /csp-report', $csp);
        self::assertStringContains('https://a.example/r', $csp);
        self::assertStringNotContains('insecure.example', $csp);
        self::assertStringNotContains('javascript', $csp);
    }

    /* ---------- 跨域隔离 ---------- */

    public function testCrossOriginIsolation(): void
    {
        $headers = $this->h->setCrossOriginIsolation(true)->toArray();

        self::assertSame('same-origin', $headers['Cross-Origin-Opener-Policy']);
        self::assertSame('same-origin', $headers['Cross-Origin-Resource-Policy']);

        $noOpener = $this->h->setCrossOriginIsolation(false)->toArray();
        self::assertArrayNotHasKey('Cross-Origin-Opener-Policy', $noOpener);
    }

    /* ---------- 便捷函数 ---------- */

    public function testSendSecurityHeadersDoesNotFatalInCli(): void
    {
        // CLI 下 headers_sent() 为真时应安全返回 0，而不是报错
        $count = \MornRain\GuardKit\morn_send_security_headers(false);
        self::assertTrue($count >= 0);
    }
}