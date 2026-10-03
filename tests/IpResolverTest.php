<?php
/**
 * IP 解析器测试。
 *
 * @package MornRain\GuardKit\Tests
 */

declare(strict_types=1);

namespace MornRain\GuardKit\Tests;

use InvalidArgumentException;
use MornRain\GuardKit\IpResolver;

/**
 * IpResolver 测试。
 */
class IpResolverTest extends TestCase
{
    /* ---------- 可信代理网段 ---------- */

    public function testCidrMatching(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8', '172.16.0.0/12', '192.168.1.1']);

        self::assertTrue($resolver->isTrusted('10.5.5.5'));
        self::assertTrue($resolver->isTrusted('172.16.0.1'));
        self::assertTrue($resolver->isTrusted('172.31.255.255'));
        self::assertTrue($resolver->isTrusted('192.168.1.1'));

        self::assertFalse($resolver->isTrusted('11.0.0.1'));
        self::assertFalse($resolver->isTrusted('172.32.0.1'), '/12 不应覆盖 172.32.x');
        self::assertFalse($resolver->isTrusted('192.168.1.2'), '单 IP 只匹配自身');
    }

    public function testWildcardMatchesExactlyOneOctet(): void
    {
        $resolver = new IpResolver(['203.0.113.*']);

        self::assertTrue($resolver->isTrusted('203.0.113.1'));
        self::assertTrue($resolver->isTrusted('203.0.113.255'));
        // 通配符必须对应 /24，不能多信任一个八位组
        self::assertFalse($resolver->isTrusted('203.0.112.1'), '203.0.113.* 不应匹配 203.0.112.x');
        self::assertFalse($resolver->isTrusted('203.0.114.1'));
    }

    public function testFullWildcardTrustsEverything(): void
    {
        $resolver = new IpResolver(['0.0.0.0/0']);
        self::assertTrue($resolver->isTrusted('8.8.8.8'));
        self::assertTrue($resolver->isTrusted('203.0.113.1'));
    }

    public function testRejectsMalformedProxyConfig(): void
    {
        $resolver = new IpResolver();

        self::assertThrows(InvalidArgumentException::class, static function () use ($resolver): void {
            $resolver->addTrustedProxy('10.0.0.0/33');
        });
        self::assertThrows(InvalidArgumentException::class, static function () use ($resolver): void {
            $resolver->addTrustedProxy('10.0.0.0/-1');
        });
        self::assertThrows(InvalidArgumentException::class, static function () use ($resolver): void {
            $resolver->addTrustedProxy('not-an-ip');
        });
        self::assertThrows(InvalidArgumentException::class, static function () use ($resolver): void {
            $resolver->addTrustedProxy('999.0.0.*');
        });
        self::assertThrows(InvalidArgumentException::class, static function () use ($resolver): void {
            $resolver->addTrustedProxy('203.0.*.5');
        }, '中途通配无法用 CIDR 精确表达，应报错');
    }

    public function testEmptyProxyStringIsIgnored(): void
    {
        $resolver = new IpResolver(['', '   ']);
        self::assertFalse($resolver->isTrusted('1.2.3.4'));
    }

    /* ---------- 解析真实 IP ---------- */

    public function testResolveWithoutTrustedProxiesIgnoresHeaders(): void
    {
        $resolver = new IpResolver();
        $server   = [
            'REMOTE_ADDR'          => '198.51.100.9',
            'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
            'HTTP_X_REAL_IP'       => '5.6.7.8',
        ];

        // REMOTE_ADDR 不是可信代理时，一切代理头都必须被忽略
        self::assertSame('198.51.100.9', $resolver->resolve($server));
    }

    public function testResolveReturnsEmptyForInvalidRemoteAddr(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        self::assertSame('', $resolver->resolve(['REMOTE_ADDR' => 'not-an-ip']));
        self::assertSame('', $resolver->resolve([]));
    }

    public function testResolveStripsTrustedProxyChainFromRight(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server   = [
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5, 10.0.0.2',
        ];

        // 从右往左剥离可信代理：10.0.0.2 是代理，203.0.113.5 才是客户端
        self::assertSame('203.0.113.5', $resolver->resolve($server));
    }

    public function testResolveRejectsForgedXffWhenChainUntrusted(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server   = [
            'REMOTE_ADDR'          => '10.0.0.1',
            // 中间混入了非可信地址，说明链被伪造
            'HTTP_X_FORWARDED_FOR' => '1.2.3.4, evil, 10.0.0.2',
        ];

        self::assertSame('10.0.0.1', $resolver->resolve($server), '链中含非法段时应放弃代理头');
    }

    public function testResolveHandlesPortSuffix(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server   = [
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5:8080',
        ];

        self::assertSame('203.0.113.5', $resolver->resolve($server));
    }

    public function testResolveHandlesIpv6Brackets(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server   = [
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '[2001:db8::1]',
        ];

        self::assertSame('2001:db8::1', $resolver->resolve($server));
    }

    public function testResolvePrefersCloudflareHeader(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server   = [
            'REMOTE_ADDR'           => '10.0.0.1',
            'HTTP_CF_CONNECTING_IP' => '203.0.113.9',
            'HTTP_X_FORWARDED_FOR'  => '198.51.100.1',
        ];

        // CF-Connecting-IP 优先级高于 XFF
        self::assertSame('203.0.113.9', $resolver->resolve($server));
    }

    public function testWithoutTrustedProxiesDisablesHeaders(): void
    {
        $resolver = (new IpResolver(['10.0.0.0/8']))->withoutTrustedProxies();
        $server   = [
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
        ];

        self::assertSame('10.0.0.1', $resolver->resolve($server));
    }

    public function testCustomHeaderPriority(): void
    {
        $resolver = (new IpResolver(['10.0.0.0/8']))->headerPriority(['HTTP_X_CUSTOM_IP']);
        $server   = [
            'REMOTE_ADDR'       => '10.0.0.1',
            'HTTP_X_CUSTOM_IP'  => '203.0.113.7',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.1',
        ];

        self::assertSame('203.0.113.7', $resolver->resolve($server));
    }

    public function testHeaderPriorityIgnoresEmptyEntries(): void
    {
        $resolver = (new IpResolver(['10.0.0.0/8']))->headerPriority(['', '  ', 'HTTP_X_REAL_IP']);
        $server   = ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.3'];

        self::assertSame('203.0.113.3', $resolver->resolve($server));
    }

    /* ---------- 辅助判断 ---------- */

    public function testIsPrivateDetectsReservedRanges(): void
    {
        $resolver = new IpResolver();

        self::assertTrue($resolver->isPrivate('192.168.1.1'));
        self::assertTrue($resolver->isPrivate('10.0.0.1'));
        self::assertTrue($resolver->isPrivate('127.0.0.1'));
        self::assertFalse($resolver->isPrivate('8.8.8.8'));
        self::assertFalse($resolver->isPrivate('invalid'));
    }

    public function testIsTrustedRejectsInvalidIp(): void
    {
        $resolver = new IpResolver(['0.0.0.0/0']);
        self::assertFalse($resolver->isTrusted(''), '空串不应因 /0 而被信任');
        self::assertFalse($resolver->isTrusted('999.1.1.1'));
    }
}