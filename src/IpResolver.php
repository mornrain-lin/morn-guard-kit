<?php
/**
 * 客户端 IP 安全解析。
 *
 * 直连场景下 REMOTE_ADDR 即为真实 IP；但当站点位于 CDN / 反向代理之后时，
 * 需要从 X-Forwarded-For、X-Real-IP、CF-Connecting-IP 等头中取值。
 * 这些头可被任意客户端伪造，因此必须显式配置「可信代理网段」，
 * 并从右往左剥离可信代理，取第一个不可信地址作为客户端 IP。
 *
 * @package MornRain\GuardKit
 */

declare(strict_types=1);

namespace MornRain\GuardKit;

use InvalidArgumentException;

/**
 * IP 解析器。
 */
class IpResolver
{
    /** @var array<int,array{0:string,1:string}> 可信代理 CIDR 列表，每项为 [网络前缀长度, 起始 IPv4 整数] */
    protected $trustedCidrs = [];

    /** @var array<int,string> 额外优先信任的请求头，按顺序尝试 */
    protected $headerPriority = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_TRUE_CLIENT_IP',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
    ];

    /** @var bool 是否信任 REMOTE_ADDR 属于可信代理时的最后一段 XFF */
    protected $trustProxyHeaders = true;

    /**
     * 构造函数。
     *
     * @param array<int,string> $trustedProxies 可信代理网段，如 ['10.0.0.0/8', '172.16.0.0/12', '203.0.113.7']。
     */
    public function __construct(array $trustedProxies = [])
    {
        foreach ($trustedProxies as $cidr) {
            $this->addTrustedProxy((string) $cidr);
        }
    }

    /**
     * 追加可信代理网段。
     *
     * 支持三种写法：
     * - 完整 IPv4：'203.0.113.7'
     * - CIDR：'203.0.113.0/24'
     * - 通配：'203.0.113.*'
     */
    public function addTrustedProxy(string $cidr): self
    {
        $cidr = trim($cidr);
        if ($cidr === '') {
            return $this;
        }

        if (strpos($cidr, '/') !== false) {
            [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, '32');
            $bits = (int) $bits;
            if ($bits < 0 || $bits > 32) {
                throw new InvalidArgumentException('非法的 CIDR 前缀长度：' . $cidr);
            }
            $ip = $this->ipToLong($subnet);
            if ($ip === null) {
                throw new InvalidArgumentException('非法的 IPv4 网段：' . $cidr);
            }
            // 掩码对齐到网段起始地址。
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
            $this->trustedCidrs[] = [$bits, $ip & $mask];

            return $this;
        }

        if (strpos($cidr, '*') !== false) {
            $parts = explode('.', $cidr);
            if (count($parts) !== 4) {
                throw new InvalidArgumentException('非法的 IPv4 通配：' . $cidr);
            }

            // 只统计**开头连续**的具体八位组。
            // 中途出现 `*`（如 203.0.*.5）无法用 CIDR 精确表达，
            // 视为非法而不是悄悄放宽成更大的网段。
            $prefixLen = 0;
            $octets    = [];
            foreach ($parts as $index => $part) {
                if ($part === '*') {
                    // 只允许出现在末尾连续位置：203.0.113.* 合法，
                    // 203.0.*.5 则无法用 CIDR 精确表达，直接拒绝。
                    if ($index !== $prefixLen) {
                        throw new InvalidArgumentException('IPv4 通配只能出现在末尾连续位置：' . $cidr);
                    }
                    $octets[] = 0;
                    continue;
                }
                // 出现过 `*` 之后又出现具体段，同样视为非法
                if ($index > $prefixLen) {
                    throw new InvalidArgumentException('IPv4 通配只能出现在末尾连续位置：' . $cidr);
                }
                if (preg_match('/^\d{1,3}$/', $part) !== 1 || (int) $part > 255) {
                    throw new InvalidArgumentException('非法的 IPv4 通配：' . $cidr);
                }
                $octets[]   = (int) $part;
                $prefixLen++;
            }

            // 203.0.113.* → 3 个具体八位组 → /24。
            // 注意此处不可写成 $prefixLen * 8 - 1：那会得到 /23，
            // 使 203.0.112.* 也被误判为可信代理，进而信任其伪造的 XFF 头。
            $bits = $prefixLen * 8;
            if ($bits > 32) {
                $bits = 32;
            }
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
            $this->trustedCidrs[] = [$bits, $this->ipToLong(implode('.', $octets)) & $mask];

            return $this;
        }

        $ip = $this->ipToLong($cidr);
        if ($ip === null) {
            throw new InvalidArgumentException('非法的 IPv4 地址：' . $cidr);
        }
        $this->trustedCidrs[] = [32, $ip];

        return $this;
    }

    /**
     * 清空可信代理配置（此时所有代理头均不可信，只用 REMOTE_ADDR）。
     */
    public function withoutTrustedProxies(): self
    {
        $this->trustedCidrs        = [];
        $this->trustProxyHeaders = false;

        return $this;
    }

    /**
     * 覆盖优先信任的请求头顺序。
     *
     * @param array<int,string> $keys $_SERVER 键名，如 ['HTTP_X_FORWARDED_FOR']。
     */
    public function headerPriority(array $keys): self
    {
        $this->headerPriority = array_values(array_filter(array_map(static function ($key) {
            return strtoupper(trim((string) $key));
        }, $keys), static function (string $key): bool {
            return $key !== '';
        }));

        return $this;
    }

    /**
     * 解析真实客户端 IP。
     *
     * @param array<string,mixed>|null $server 留空则使用 $_SERVER。
     * @return string 非法时返回空串。
     */
    public function resolve(?array $server = null): string
    {
        $server = $server ?? $_SERVER;
        $remote = $this->readServer($server, 'REMOTE_ADDR');

        // REMOTE_ADDR 本身不合法时无法继续。
        if (!filter_var($remote, FILTER_VALIDATE_IP)) {
            return $this->normalizeValid($remote);
        }

        if (!$this->trustProxyHeaders) {
            return $remote;
        }

        // REMOTE_ADDR 不是可信代理 → 客户端直连，忽略一切代理头。
        if (!$this->isTrusted($remote)) {
            return $remote;
        }

        foreach ($this->headerPriority as $key) {
            $raw = $this->readServer($server, $key);
            if ($raw === '') {
                continue;
            }

            if ($key === 'HTTP_X_FORWARDED_FOR') {
                $candidate = $this->pickFromForwardedFor($raw);
            } else {
                $candidate = trim(explode(',', $raw)[0]);
            }

            if ($candidate !== '' && $this->normalizeValid($candidate) !== '') {
                return $this->normalizeValid($candidate);
            }
        }

        return $remote;
    }

    /**
     * 判断某 IP 是否落在可信代理网段。
     */
    public function isTrusted(string $ip): bool
    {
        $long = $this->ipToLong($ip);
        if ($long === null) {
            return false;
        }

        foreach ($this->trustedCidrs as [$bits, $start]) {
            if ($bits === 0) {
                return true;
            }
            $mask = -1 << (32 - $bits);
            if (($long & $mask) === $start) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断 IP 是否为私有 / 保留网段。
     */
    public function isPrivate(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false && filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * 从 X-Forwarded-For 中选出真实客户端 IP。
     *
     * 规则：从右往左遍历，跳过所有可信代理地址，第一个不可信地址即为客户端 IP。
     * 若整条链都是可信代理，则取最左侧第一个地址（可能是客户端本机）。
     */
    protected function pickFromForwardedFor(string $value): string
    {
        $parts = array_map('trim', explode(',', $value));
        $parts = array_values(array_filter($parts, static function (string $item): bool {
            return $item !== '';
        }));
        if ($parts === []) {
            return '';
        }

        for ($i = count($parts) - 1; $i >= 0; $i--) {
            $ip = $this->stripPort($parts[$i]);
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                // 出现非法段说明链不可信，直接放弃代理头。
                return '';
            }
            if (!$this->isTrusted($ip)) {
                return $ip;
            }
        }

        return $this->stripPort($parts[0]);
    }

    /**
     * 去掉 IPv4 端口后缀与方括号（IPv6）。
     */
    protected function stripPort(string $ip): string
    {
        $ip = trim($ip);
        if ($ip === '') {
            return '';
        }
        if ($ip[0] === '[') {
            $pos = strpos($ip, ']');
            if ($pos !== false) {
                return substr($ip, 1, $pos - 1);
            }
        }
        // 只有一个冒号时才可能是「IP:端口」。
        if (substr_count($ip, ':') === 1 && strpos($ip, '.') !== false) {
            $ip = substr($ip, 0, strpos($ip, ':'));
        }

        return trim($ip);
    }

    /**
     * 校验并规范化 IP，未通过则返回空串。
     */
    protected function normalizeValid(string $ip): string
    {
        $ip = $this->stripPort($ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        return $ip;
    }

    /**
     * 读取服务器变量。
     *
     * @param array<string,mixed> $server
     */
    protected function readServer(array $server, string $key): string
    {
        return isset($server[$key]) && is_scalar($server[$key]) ? (string) $server[$key] : '';
    }

    /**
     * IPv4 转无符号整数。
     */
    protected function ipToLong(string $ip): ?int
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }
        $long = ip2long($ip);
        if ($long === false) {
            return null;
        }

        return $long & 0xFFFFFFFF;
    }
}
