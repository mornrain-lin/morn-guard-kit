<?php
/**
 * 安全工具集测试。
 *
 * 覆盖三类场景：
 * - 正常路径：功能按预期工作；
 * - 边界情况：空值、超长输入、多字节、非法类型；
 * - 安全路径：注入、XSS、路径穿越、令牌篡改、重放。
 *
 * @package MornRain\GuardKit\Tests
 */

declare(strict_types=1);

namespace MornRain\GuardKit\Tests;

use InvalidArgumentException;
use MornRain\GuardKit\IpResolver;
use MornRain\GuardKit\RequestGuard;
use MornRain\GuardKit\Sanitizer;
use MornRain\GuardKit\SecurityHeaders;
use RuntimeException;

/**
 * RequestGuard 测试。
 */
class RequestGuardTest extends TestCase
{
    /** @var string 临时状态目录 */
    private $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/morn-guard-test-' . getmypid() . '-' . uniqid();
    }

    protected function tearDown(): void
    {
        self::removeTree($this->dir);
    }

    /**
     * 递归删除测试目录。
     */
    private static function removeTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($dir);
    }

    /**
     * 构造被测实例。
     */
    private function guard(string $action = 'test_action'): RequestGuard
    {
        return new RequestGuard($action, 43200, $this->dir);
    }

    /* ---------- 构造与配置 ---------- */

    public function testConstructorRejectsEmptyAction(): void
    {
        $error = self::assertThrows(
            InvalidArgumentException::class,
            static function (): void {
                new RequestGuard('');
            }
        );
        self::assertStringContains('不能为空', $error->getMessage());
    }

    public function testConstructorRejectsTooShortLifetime(): void
    {
        self::assertThrows(InvalidArgumentException::class, static function (): void {
            new RequestGuard('act', 10);
        });
    }

    public function testAllowMethodsRejectsEmptyList(): void
    {
        $guard = $this->guard();
        self::assertThrows(InvalidArgumentException::class, static function () use ($guard): void {
            $guard->allowMethods([]);
        });
    }

    public function testAllowMethodsNormalizesCaseAndWhitespace(): void
    {
        $guard = $this->guard();
        self::assertDoesNotThrow(static function () use ($guard): void {
            $guard->allowMethods([' post ', 'PUT', '!!!bad!!!']);
        });
        self::assertTrue($guard->isMethodAllowed('POST'));
        self::assertTrue($guard->isMethodAllowed('put'));
        self::assertFalse($guard->isMethodAllowed('GET'), '非法方法应被过滤掉');
    }

    public function testIsMethodAllowedWithEmptyServerVar(): void
    {
        $guard = $this->guard();
        $guard->allowMethods(['POST']);
        // 没有 REQUEST_METHOD 时应判定为不允许，而不是误判成允许
        self::assertFalse($guard->isMethodAllowed(''));
    }

    /* ---------- nonce ---------- */

    public function testNonceRoundTrip(): void
    {
        $guard = $this->guard();
        self::assertTrue($guard->verifyNonce($guard->createNonce()));
    }

    public function testNonceIsScopedByAction(): void
    {
        $nonce = $this->guard('action_a')->createNonce();
        $other = new RequestGuard('action_b', 43200, $this->dir);

        self::assertFalse($other->verifyNonce($nonce), '不同 action 的 nonce 不应互相通过');
    }

    public function testNonceRejectsTamperedToken(): void
    {
        $guard  = $this->guard();
        $nonce  = $guard->createNonce();
        $broken = substr($nonce, 0, -2) . 'ab';

        self::assertFalse($guard->verifyNonce($broken), '签名被篡改必须拒绝');
    }

    public function testNonceRejectsTamperedTimestamp(): void
    {
        $guard = $this->guard();
        $nonce = $guard->createNonce();
        [$ts, $token] = explode('|', $nonce);

        // 时间戳必须受完整性保护，否则可被改写以延长有效期
        self::assertFalse($guard->verifyNonce(((int) $ts + 99999) . '|' . $token));
    }

    public function testNonceRejectsExpired(): void
    {
        $guard = new RequestGuard('act', 60, $this->dir);
        $nonce = $guard->createNonce();
        // 构造一个 1 小时前的时间戳 + 任意签名
        $old = (time() - 3600) . '|' . str_repeat('a', 64);

        self::assertFalse($guard->verifyNonce($old), '过期 nonce 必须拒绝');
        self::assertTrue(strlen($nonce) > 0);
    }

    public function testVerifyNonceRejectsEmptyAndOversized(): void
    {
        $guard = $this->guard();
        self::assertFalse($guard->verifyNonce(''));
        self::assertFalse($guard->verifyNonce(str_repeat('a', 500)), '超长 nonce 必须直接拒绝');
    }

    public function testVerifyNonceRejectsMalformedShapes(): void
    {
        $guard = $this->guard();
        self::assertFalse($guard->verifyNonce('no-separator'));
        self::assertFalse($guard->verifyNonce('a|b|c'));
        self::assertFalse($guard->verifyNonce('abc|def'), '非数字时间戳必须拒绝');
        self::assertFalse($guard->verifyNonce('|' . str_repeat('a', 64)));
        self::assertFalse($guard->verifyNonce('0|' . str_repeat('a', 64)), '时间戳为 0 必须拒绝');
    }

    public function testExtractNonceFromSource(): void
    {
        $guard = $this->guard();
        self::assertSame('', $guard->extractNonce([]));
        self::assertSame('abc', $guard->extractNonce([$guard->nonceName() => 'abc']));
        // 非字符串值不应触发类型错误
        self::assertSame('', $guard->extractNonce([$guard->nonceName() => ['x']]));
    }

    public function testNonceFieldIsEscaped(): void
    {
        $guard = $this->guard();
        $field = $guard->nonceField(false);

        self::assertStringContains('type="hidden"', $field);
        self::assertStringContains('name="_morn_nonce"', $field);
        // 标签必须闭合，不能被注入截断
        self::assertSame(1, substr_count($field, '<input'));
        self::assertStringContains('/>', $field);
    }

    /* ---------- CSRF ---------- */

    public function testCsrfVerifyFailsWithoutCookie(): void
    {
        $guard = $this->guard();
        // 没有对应 Cookie 时任何令牌都必须失败
        self::assertFalse($guard->verifyCsrf('anything'));
        self::assertFalse($guard->verifyCsrf(''));
    }

    public function testCsrfTokenIsStableForSameSeed(): void
    {
        $guard = $this->guard();
        $_COOKIE['morn_csrf_test'] = str_repeat('a', 32);
        $first  = $guard->csrfToken('morn_csrf_test');
        $second = $guard->csrfToken('morn_csrf_test');

        self::assertSame($first, $second, '同一种子必须派生出同一令牌');
        unset($_COOKIE['morn_csrf_test']);
    }

    public function testCsrfVerifyRejectsWrongToken(): void
    {
        $guard = $this->guard();
        $_COOKIE['morn_csrf_test2'] = str_repeat('b', 32);

        self::assertFalse($guard->verifyCsrf('wrong-token', 'morn_csrf_test2'));
        self::assertFalse($guard->verifyCsrf(str_repeat("\0", 64), 'morn_csrf_test2'));
        unset($_COOKIE['morn_csrf_test2']);
    }

    /* ---------- 请求签名 ---------- */

    public function testSignRequestRejectsWeakSecret(): void
    {
        $guard = $this->guard();
        self::assertThrows(RuntimeException::class, static function () use ($guard): void {
            $guard->signRequest('short', 'GET', '/x');
        });
    }

    public function testSignatureRoundTrip(): void
    {
        $guard  = $this->guard();
        $secret = str_repeat('s', 32);
        $sig    = $guard->signRequest($secret, 'post', '/api/v1');

        self::assertTrue($guard->verifyRequestSignature(
            $secret,
            'POST',
            '/api/v1',
            $sig['timestamp'],
            $sig['signature'],
            $sig['nonce']
        ), '方法名大小写不应影响校验');
    }

    public function testSignatureRejectsReplay(): void
    {
        $guard  = $this->guard();
        $secret = str_repeat('s', 32);
        $sig    = $guard->signRequest($secret, 'POST', '/api/v1');

        self::assertTrue($guard->verifyRequestSignature(
            $secret,
            'POST',
            '/api/v1',
            $sig['timestamp'],
            $sig['signature'],
            $sig['nonce']
        ));
        self::assertFalse($guard->verifyRequestSignature(
            $secret,
            'POST',
            '/api/v1',
            $sig['timestamp'],
            $sig['signature'],
            $sig['nonce']
        ), '同一 nonce 只能使用一次');
    }

    public function testSignatureRejectsInvalidHexNonce(): void
    {
        $guard  = $this->guard();
        $secret = str_repeat('s', 32);
        $sig    = $guard->signRequest($secret, 'POST', '/api/v1');

        // 非十六进制 nonce 曾导致 hex2bin() 返回 false 并被拼进待签名串
        self::assertFalse($guard->verifyRequestSignature(
            $secret,
            'POST',
            '/api/v1',
            $sig['timestamp'],
            $sig['signature'],
            'zzzz-not-hex'
        ));
    }

    public function testSignatureRejectsTamperedFields(): void
    {
        $guard  = $this->guard();
        $secret = str_repeat('s', 32);
        $sig    = $guard->signRequest($secret, 'POST', '/api/v1');

        // 换路径
        self::assertFalse($guard->verifyRequestSignature(
            $secret,
            'POST',
            '/api/v2',
            $sig['timestamp'],
            $sig['signature'],
            $sig['nonce']
        ));
        // 换密钥
        self::assertFalse($guard->verifyRequestSignature(
            str_repeat('x', 32),
            'POST',
            '/api/v1',
            $sig['timestamp'],
            $sig['signature'],
            $sig['nonce']
        ));
        // 时间戳超出窗口
        self::assertFalse($guard->verifyRequestSignature(
            $secret,
            'POST',
            '/api/v1',
            (string) (time() - 100000),
            $sig['signature'],
            $sig['nonce']
        ));
        // 空值
        self::assertFalse($guard->verifyRequestSignature($secret, 'POST', '/api/v1', '', '', ''));
    }

    /* ---------- 限流 ---------- */

    public function testRateLimitRejectsInvalidConfig(): void
    {
        $guard = $this->guard();
        self::assertThrows(InvalidArgumentException::class, static function () use ($guard): void {
            $guard->rateLimit('k', 0);
        });
        self::assertThrows(InvalidArgumentException::class, static function () use ($guard): void {
            $guard->rateLimit('k', 10, 0.0);
        });
    }

    public function testRateLimitAllowsBurstThenBlocks(): void
    {
        $guard = $this->guard('rate_test');
        $retry = 0;

        // 容量 3，应放行前 3 次
        for ($i = 0; $i < 3; $i++) {
            self::assertTrue($guard->rateLimit('ip-1', 3, 0.01, $retry), "第 {$i} 次应放行");
        }
        self::assertFalse($guard->rateLimit('ip-1', 3, 0.01, $retry), '超出容量应限流');
        self::assertTrue($retry > 0, '限流时应给出建议等待秒数');
    }

    public function testRateLimitIsolatesKeys(): void
    {
        $guard = $this->guard('rate_iso');
        self::assertTrue($guard->rateLimit('ip-a', 1, 0.01));
        self::assertFalse($guard->rateLimit('ip-a', 1, 0.01));
        // 不同维度应独立计数
        self::assertTrue($guard->rateLimit('ip-b', 1, 0.01), '不同 key 不应互相影响');
    }

    /* ---------- Referer ---------- */

    public function testTrustedRefererAllowsWhenWhitelistEmpty(): void
    {
        $guard = $this->guard();
        self::assertTrue($guard->isTrustedReferer([]), '白名单为空时不做限制');
    }

    public function testTrustedRefererMatchesOriginHost(): void
    {
        $guard = $this->guard();
        $_SERVER['HTTP_ORIGIN']   = 'https://example.com';
        $_SERVER['HTTP_REFERER']  = '';

        self::assertTrue($guard->isTrustedReferer(['example.com']));

        $_SERVER['HTTP_ORIGIN'] = 'https://evil.com';
        self::assertFalse($guard->isTrustedReferer(['example.com']), '不同源必须拒绝');

        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER']);
    }
}