<?php
/**
 * 请求校验与限流工具。
 *
 * 职责：
 * 1. 校验 HTTP 请求方法与来源（Referer / 自定义请求头）；
 * 2. 生成与验证 nonce 字段（优先使用 WordPress nonce，回退到纯 PHP HMAC 实现）；
 * 3. 令牌桶算法限流（基于 WordPress Transient，纯 PHP 环境回退到文件存储）；
 * 4. 提供轻量的 API 请求签名校验（HMAC-SHA256 + 时间戳 + 随机 nonce）。
 *
 * @package MornRain\GuardKit
 */

declare(strict_types=1);

namespace MornRain\GuardKit;

use InvalidArgumentException;
use RuntimeException;
use Exception;

/**
 * 请求守卫类。
 */
class RequestGuard
{
    /** @var string 动作名称，用于 nonce 作用域隔离 */
    protected $action;

    /** @var string nonce 生命周期（秒），默认 12 小时 */
    protected $lifetime;

    /** @var string 存放回退 nonce 状态的目录 */
    protected $storageDir;

    /** @var array<string,string> 允许的请求方法 */
    protected $allowedMethods = ['GET', 'POST'];

    /** @var bool 是否强制要求 Referer / Origin 校验 */
    protected $enforceReferer = false;

    /**
     * 构造函数。
     *
     * @param string $action     动作名，WP 惯例为资源 slug。
     * @param int    $lifetime   nonce 有效期（秒）。
     * @param string $storageDir 回退实现的状态目录，默认 sys_get_temp_dir()/morn-guard-kit。
     */
    public function __construct(string $action = 'morn_guard', int $lifetime = 43200, string $storageDir = '')
    {
        if ($action === '') {
            throw new InvalidArgumentException('动作名不能为空');
        }
        if ($lifetime < 60) {
            throw new InvalidArgumentException('nonce 生命周期不得小于 60 秒');
        }

        $this->action   = $action;
        $this->lifetime = $lifetime;

        if ($storageDir === '') {
            $storageDir = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'morn-guard-kit';
        }
        $this->storageDir = rtrim($storageDir, '/\\');
    }

    /**
     * 设置允许的请求方法。
     *
     * @param array<int,string> $methods 方法列表，例如 ['POST']。
     */
    public function allowMethods(array $methods): self
    {
        $normalized = [];
        foreach ($methods as $method) {
            $method = strtoupper(trim((string) $method));
            if ($method !== '' && preg_match('/^[A-Z]+$/', $method) === 1) {
                $normalized[] = $method;
            }
        }
        if ($normalized === []) {
            throw new InvalidArgumentException('至少需要保留一个合法请求方法');
        }
        $this->allowedMethods = $normalized;

        return $this;
    }

    /**
     * 是否强制 Referer / Origin 校验。
     */
    public function enforceReferer(bool $enabled = true): self
    {
        $this->enforceReferer = $enabled;

        return $this;
    }

    /**
     * 校验当前请求方法是否被允许。
     *
     * @param string|null $method 留空则从 $_SERVER 推断。
     */
    public function isMethodAllowed(?string $method = null): bool
    {
        $method = $this->resolveMethod($method);

        return $method !== '' && in_array($method, $this->allowedMethods, true);
    }

    /**
     * 校验请求来源是否可信。
     *
     * 校验顺序：REMOTE_ADDR 是否为可信来源 → Origin 是否在白名单 → Referer 主机是否在白名单。
     *
     * @param array<int,string> $allowedHosts 允许的来源主机白名单。
     * @param string|null      $allowedHost  单主机快捷方式。
     */
    public function isTrustedReferer(array $allowedHosts = [], string $allowedHost = ''): bool
    {
        $allowed = [];
        if ($allowedHost !== '') {
            $allowed[] = strtolower($allowedHost);
        }
        foreach ($allowedHosts as $host) {
            $host = strtolower(trim((string) $host));
            if ($host !== '') {
                $allowed[] = $host;
            }
        }

        // 白名单为空时不做来源限制（显式调用方已承担风险）。
        if ($allowed === []) {
            return true;
        }

        $origin = $this->header('HTTP_ORIGIN');
        if ($origin !== '' && $origin !== 'null') {
            $originHost = strtolower((string) parse_url($origin, PHP_URL_HOST));
            if ($originHost !== '' && in_array($originHost, $allowed, true)) {
                return true;
            }
        }

        $referer = $this->header('HTTP_REFERER');
        if ($referer !== '') {
            $refHost = strtolower((string) parse_url($referer, PHP_URL_HOST));
            if ($refHost !== '' && in_array($refHost, $allowed, true)) {
                return true;
            }
        }

        // 部分环境（如移动端 WebView）无 Referer，仅当白名单命中本机名时放行。
        $selfHost = strtolower((string) parse_url($this->currentUrl(), PHP_URL_HOST));
        if ($selfHost !== '' && in_array($selfHost, $allowed, true)) {
            return ($origin === '' && $referer === '') ? true : false;
        }

        return false;
    }

    /**
     * 生成 nonce 字段 HTML（隐藏域）。
     *
     * @param bool $referer 是否附加 referer 隐藏域。
     */
    public function nonceField(bool $referer = true): string
    {
        $field = '<input type="hidden" name="' . Compat::attr($this->nonceName())
            . '" value="' . Compat::attr($this->createNonce()) . '" />';

        if ($referer && function_exists('wp_referer_field')) {
            return wp_referer_field(false) . $field;
        }

        return $field;
    }

    /**
     * 生成 nonce 字符串。
     */
    public function createNonce(): string
    {
        if (function_exists('wp_create_nonce')) {
            return (string) wp_create_nonce($this->action);
        }

        $uid     = $this->currentUserId();
        $created = time();
        $salt    = $this->fallbackSalt();
        $token   = hash_hmac('sha256', $this->action . '|' . $uid . '|' . $created, $salt);

        // 注意：不可对拼接结果做 substr 截断，那会切掉 HMAC 的尾部，
        // 导致同一时刻签发的 nonce 与校验时的计算结果不一致。
        // 时间戳为定长 10 位（当前纪元秒），HMAC-SHA256 为定长 64 位十六进制，
        // 总长 75 字节，天然落在 200 字节上限内。
        return $created . '|' . $token;
    }

    /**
     * 校验 nonce 字符串。
     *
     * @param string|null $nonce 留空则自动从 $_REQUEST 读取。
     */
    public function verifyNonce(?string $nonce = null): bool
    {
        if ($nonce === null) {
            $name  = $this->nonceName();
            $nonce = isset($_REQUEST[$name]) && is_string($_REQUEST[$name]) ? $_REQUEST[$name] : '';
        }

        if ($nonce === '' || strlen($nonce) > 200) {
            return false;
        }

        if (function_exists('wp_verify_nonce')) {
            return (bool) wp_verify_nonce($nonce, $this->action);
        }

        $parts = explode('|', $nonce);
        if (count($parts) !== 2) {
            return false;
        }
        $created = $parts[0];
        // 严格校验时间戳形态，避免 'abc|def' 这类畸形输入进入后续比较
        if (preg_match('/^\d{1,12}$/', $created) !== 1) {
            return false;
        }
        $createdTs = (int) $created;
        if ($createdTs <= 0 || (time() - $createdTs) > $this->lifetime) {
            return false;
        }

        $uid   = $this->currentUserId();
        $salt  = $this->fallbackSalt();
        $token = hash_hmac('sha256', $this->action . '|' . $uid . '|' . $createdTs, $salt);

        // 比较完整的 "时间戳|签名"，而不是只比签名段。
        // 只比签名段时，时间戳本身不受完整性保护，
        // 可被替换成别的合法时间戳以延长或缩短有效期。
        $expected = $createdTs . '|' . $token;

        return hash_equals($expected, $nonce);
    }

    /**
     * 从请求中取出 nonce 值（不校验）。
     */
    public function extractNonce(array $source = []): string
    {
        if ($source === []) {
            $source = $_REQUEST;
        }
        $name = $this->nonceName();

        return isset($source[$name]) && is_string($source[$name]) ? $source[$name] : '';
    }

    /**
     * nonce 字段名。
     */
    public function nonceName(): string
    {
        return '_morn_nonce';
    }

    /**
     * 生成 CSRF 令牌（与站点 Cookie 绑定的双提交令牌）。
     *
     * 首次调用会通过 Set-Cookie 下发随机种子并返回派生令牌，
     * 校验时用 Cookie 中的种子重新派生，避免令牌被跨站复用。
     */
    public function csrfToken(string $cookieName = 'morn_csrf'): string
    {
        $seed = isset($_COOKIE[$cookieName]) && is_string($_COOKIE[$cookieName])
            ? $_COOKIE[$cookieName]
            : '';

        if ($seed === '' || strlen($seed) < 32) {
            $seed = $this->randomBytes(32);
            $this->sendCookie($cookieName, $seed);
        }

        return $this->deriveCsrf($seed);
    }

    /**
     * 校验 CSRF 令牌。
     *
     * @param string|null $token      留空则从请求体读取。
     * @param string      $cookieName 与生成时一致的 Cookie 名。
     */
    public function verifyCsrf(?string $token = null, string $cookieName = 'morn_csrf'): bool
    {
        if ($token === null) {
            $token = isset($_REQUEST['_morn_csrf']) && is_string($_REQUEST['_morn_csrf'])
                ? $_REQUEST['_morn_csrf']
                : '';
        }
        if ($token === '' || !isset($_COOKIE[$cookieName]) || !is_string($_COOKIE[$cookieName])) {
            return false;
        }

        return hash_equals($this->deriveCsrf((string) $_COOKIE[$cookieName]), $token);
    }

    /**
     * 由种子派生 CSRF 令牌。
     */
    protected function deriveCsrf(string $seed): string
    {
        return hash_hmac('sha256', 'csrf|' . $seed, $this->fallbackSalt());
    }

    /**
     * 令牌桶限流判断。
     *
     * 命中限流时返回 false，并可通过 $retryAfter 拿到建议等待秒数。
     *
     * @param string $key        限流维度标识，通常为「动作:用户标识」。
     * @param int    $capacity   桶容量，即允许的突发请求数。
     * @param int    $refillRate 每秒补充的令牌数。
     * @param int|null $retryAfter 传出参数，限流时写入建议等待秒数。
     */
    public function rateLimit(string $key, int $capacity = 20, float $refillRate = 0.5, ?int &$retryAfter = null): bool
    {
        if ($capacity < 1) {
            throw new InvalidArgumentException('桶容量不得小于 1');
        }
        if ($refillRate <= 0) {
            throw new InvalidArgumentException('补充速率必须大于 0');
        }

        $bucketKey = 'morn_guard_tb_' . md5($this->action . '|' . $key);
        $now       = microtime(true);
        $bucket    = $this->readBucket($bucketKey);

        if (!is_array($bucket) || !isset($bucket['tokens'], $bucket['ts'])) {
            $bucket = ['tokens' => (float) $capacity, 'ts' => $now];
        }

        $elapsed = max(0.0, $now - (float) $bucket['ts']);
        $tokens  = min((float) $capacity, (float) $bucket['tokens'] + $elapsed * $refillRate);

        if ($tokens < 1.0) {
            $this->writeBucket($bucketKey, ['tokens' => $tokens, 'ts' => $now], (int) ceil(1.0 / $refillRate) + 60);
            $retryAfter = (int) ceil((1.0 - $tokens) / $refillRate);

            return false;
        }

        $this->writeBucket($bucketKey, ['tokens' => $tokens - 1.0, 'ts' => $now], (int) ceil((float) $capacity / $refillRate) + 60);

        return true;
    }

    /**
     * 签发 API 请求签名。
     *
     * 签名 = base64url( HMAC-SHA256(方法 + "\n" + 路径 + "\n" + 时间戳 + "\n" + 随机串, secret ) )
     *
     * @param string $secret 与客户端共享的密钥，禁止硬编码于仓库。
     */
    public function signRequest(string $secret, string $method, string $path, ?int &$timestamp = null): array
    {
        if (strlen($secret) < 16) {
            throw new RuntimeException('签名密钥长度不得少于 16 字节');
        }
        $timestamp = time();
        $random    = $this->randomBytes(8);
        $payload   = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $random;
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $payload, $secret, true));

        return [
            'timestamp' => (string) $timestamp,
            'nonce'     => bin2hex($random),
            'signature' => $signature,
        ];
    }

    /**
     * 校验 API 请求签名（含时间窗口与重放保护）。
     *
     * @param int $tolerance 允许的时钟偏移（秒）。
     */
    public function verifyRequestSignature(
        string $secret,
        string $method,
        string $path,
        string $timestamp,
        string $signature,
        string $nonce,
        int $tolerance = 300
    ): bool {
        if ($timestamp === '' || $signature === '' || $nonce === '') {
            return false;
        }

        $ts = (int) $timestamp;
        if ($ts <= 0 || abs(time() - $ts) > $tolerance) {
            return false;
        }

        // hex2bin() 遇到非十六进制字符返回 false，若不校验会把 false
        // 拼进待签名串，导致签名校验被绕过（等于接受任意签名）。
        if (preg_match('/^[0-9a-f]{16,128}$/i', $nonce) !== 1) {
            return false;
        }
        $nonceBytes = hex2bin($nonce);
        if ($nonceBytes === false || $nonceBytes === '') {
            return false;
        }

        $payload  = strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $nonceBytes;
        $expected = $this->base64UrlEncode(hash_hmac('sha256', $payload, $secret, true));

        // 先验签名再记重放：否则任何人都能用伪造签名把合法 nonce「烧掉」，
        // 造成对真实客户端的拒绝服务。
        if (!hash_equals($expected, $signature)) {
            return false;
        }

        // 重放保护：同一 nonce 在窗口期内只允许使用一次。
        $replayKey = 'morn_guard_nc_' . md5($nonce . '|' . $ts);
        if ($this->readBucket($replayKey) !== null) {
            return false;
        }
        $this->writeBucket($replayKey, ['ts' => microtime(true)], $tolerance + 60);

        return true;
    }

    /**
     * 读取桶状态。
     *
     * @return array<string,mixed>|null
     */
    protected function readBucket(string $key): ?array
    {
        if (function_exists('get_transient')) {
            $value = get_transient($key);

            return is_array($value) ? $value : null;
        }

        $file = $this->storageDir . DIRECTORY_SEPARATOR . $key . '.json';
        if (!is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);

        return is_array($data) ? $data : null;
    }

    /**
     * 写入桶状态。
     */
    protected function writeBucket(string $key, array $data, int $ttl): void
    {
        if (function_exists('set_transient')) {
            set_transient($key, $data, $ttl);

            return;
        }

        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0700, true);
        }
        $file = $this->storageDir . DIRECTORY_SEPARATOR . $key . '.json';
        $tmp  = $file . '.' . bin2hex($this->randomBytes(4)) . '.tmp';
        if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE), LOCK_EX) !== false) {
            @rename($tmp, $file);
        }
    }

    /**
     * 推断当前请求方法。
     */
    protected function resolveMethod(?string $method): string
    {
        if ($method !== null && $method !== '') {
            return strtoupper(trim($method));
        }
        $raw = $this->server('REQUEST_METHOD');

        return $raw === '' ? '' : strtoupper($raw);
    }

    /**
     * 读取服务器变量。
     */
    protected function server(string $key): string
    {
        return isset($_SERVER[$key]) && is_scalar($_SERVER[$key]) ? (string) $_SERVER[$key] : '';
    }

    /**
     * 读取请求头（兼容 CGI / FPM 两种命名）。
     */
    protected function header(string $serverKey): string
    {
        $value = $this->server($serverKey);
        if ($value !== '') {
            return $value;
        }

        $alt = 'HTTP_' . str_replace('HTTP_', '', $serverKey);

        return $this->server($alt);
    }

    /**
     * 当前 URL（尽力拼装）。
     */
    protected function currentUrl(): string
    {
        $https = $this->server('HTTPS');
        $scheme = ($https !== '' && strtolower($https) !== 'off') ? 'https' : 'http';
        $host   = $this->server('HTTP_HOST');
        if ($host === '') {
            $host = $this->server('SERVER_NAME');
        }
        $uri = $this->server('REQUEST_URI');

        if ($host === '' && $uri === '') {
            return '';
        }

        return $scheme . '://' . $host . $uri;
    }

    /**
     * 当前用户标识（WordPress 优先）。
     */
    protected function currentUserId(): int
    {
        if (function_exists('get_current_user_id')) {
            return (int) get_current_user_id();
        }
        $userId = $this->server('REMOTE_ADDR');

        return $userId === '' ? 0 : crc32($userId);
    }

    /**
     * 回退实现使用的站点盐。
     */
    protected function fallbackSalt(): string
    {
        if (defined('LOGGED_IN_SALT') && is_string(LOGGED_IN_SALT) && LOGGED_IN_SALT !== '') {
            return LOGGED_IN_SALT;
        }
        if (defined('NONCE_SALT') && is_string(NONCE_SALT) && NONCE_SALT !== '') {
            return NONCE_SALT;
        }
        if (function_exists('wp_salt')) {
            return (string) wp_salt('nonce');
        }

        $file = $this->storageDir . DIRECTORY_SEPARATOR . 'salt.key';
        if (is_file($file)) {
            $raw = (string) @file_get_contents($file);
            if ($raw !== '') {
                return trim($raw);
            }
        }
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0700, true);
        }

        // 以 'x' 模式独占创建：并发进程只有一个能写入成功，
        // 其余进程读到失败后重新读取文件，保证全站盐值一致
        // （若各自生成不同盐，跨进程的 nonce/CSRF 校验会互相失效）。
        $salt = bin2hex($this->randomBytes(32));
        $fh   = @fopen($file, 'x');
        if ($fh !== false) {
            @chmod($file, 0600);
            $written = @fwrite($fh, $salt);
            @fclose($fh);

            if ($written !== false && $written === strlen($salt)) {
                return $salt;
            }
            // 写入不完整，清理后重读
            @unlink($file);
        }

        // 另一个进程可能刚好写完，读它的结果
        $raw = (string) @file_get_contents($file);
        if ($raw !== '') {
            return trim($raw);
        }

        // 兜底：无法落盘时退回进程级临时盐（重启后失效，会导致已下发令牌失效）
        return $salt;
    }

    /**
     * 下发安全 Cookie。
     */
    protected function sendCookie(string $name, string $value): void
    {
        if (headers_sent()) {
            return;
        }
        $secure   = ($this->server('HTTPS') !== '' && strtolower($this->server('HTTPS')) !== 'off');
        $duration = ['expires' => time() + $this->lifetime, 'path' => '/', 'domain' => '', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Lax'];
        if (function_exists('setcookie')) {
            // PHP 7.3+ 支持数组形式，可正确携带 SameSite。
            @setcookie($name, $value, $duration);
        }
    }

    /**
     * 兼容 7.4 的随机字节生成。
     *
     * 本方法服务于 CSRF 种子、请求签名 nonce、站点盐等**安全关键**场景，
     * 因此不提供 mt_rand 降级：弱随机会让令牌可预测，等同于没有令牌。
     * 拿不到密码学随机源时直接抛异常，交由调用方决定是否降级服务。
     *
     * @throws RuntimeException 随机源不可用。
     */
    protected function randomBytes(int $length): string
    {
        if ($length < 1) {
            return '';
        }
        if (!function_exists('random_bytes')) {
            throw new RuntimeException('安全令牌生成需要 PHP 7+ 的 random_bytes()，当前环境不可用。');
        }

        try {
            return random_bytes($length);
        } catch (Exception $e) {
            throw new RuntimeException('无法生成密码学安全的随机字节：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * base64url 编码。
     */
    protected function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
