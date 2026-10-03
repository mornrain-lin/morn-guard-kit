<?php
/**
 * morn-guard-kit 使用示例。
 *
 * 运行方式（CLI）：
 *   php examples/demo.php
 *
 * 该示例不依赖 WordPress，可直接在任意 PHP 7.4+ 环境中运行。
 */

declare(strict_types=1);

require __DIR__ . '/../src/Compat.php';
require __DIR__ . '/../src/RequestGuard.php';
require __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Sanitizer.php';
require __DIR__ . '/../src/IpResolver.php';

use MornRain\GuardKit\IpResolver;
use MornRain\GuardKit\RequestGuard;
use MornRain\GuardKit\Sanitizer;
use MornRain\GuardKit\SecurityHeaders;

function section(string $title): void
{
    echo PHP_EOL . '=== ' . $title . ' ===' . PHP_EOL;
}

/* ------------------------------------------------------------------ */
section('1. 请求方法与来源校验');

$guard = new RequestGuard('morn_demo_submit');

$guard->allowMethods(['POST', 'PUT']);
var_dump($guard->isMethodAllowed('POST'));   // bool(true)
var_dump($guard->isMethodAllowed('GET'));    // bool(false)

$trusted = $guard->isTrustedReferer(['example.com', 'www.example.com']);
var_dump($trusted);   // CLI 环境无 Referer，且本机名不在白名单 → bool(false)

// 模拟带 Referer 的浏览器请求
$_SERVER['HTTP_HOST']       = 'example.com';
$_SERVER['REQUEST_URI']     = '/contact';
$_SERVER['HTTP_REFERER']    = 'https://example.com/contact?p=1';
var_dump($guard->isTrustedReferer(['example.com']));   // bool(true)

$_SERVER['HTTP_REFERER']    = 'https://evil.example.net/steal';
var_dump($guard->isTrustedReferer(['example.com']));   // bool(false)
unset($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']);

/* ------------------------------------------------------------------ */
section('2. nonce 生成与校验（纯 PHP 回退实现）');

$token = $guard->createNonce();
echo 'nonce: ' . $token . PHP_EOL;
var_dump($guard->verifyNonce($token));            // bool(true)
var_dump($guard->verifyNonce($token . 'x'));      // bool(false)
var_dump($guard->verifyNonce('garbage'));         // bool(false)

echo 'nonce 字段 HTML: ' . $guard->nonceField(false) . PHP_EOL;

/* ------------------------------------------------------------------ */
section('3. 令牌桶限流（容量 3，每秒补 1 个）');

$limiter = new RequestGuard('morn_demo_limit', 3600, sys_get_temp_dir() . '/morn-guard-demo');
$key     = 'demo-user-1';

for ($i = 1; $i <= 5; $i++) {
    $retryAfter = null;
    $allowed    = $limiter->rateLimit($key, 3, 1.0, $retryAfter);
    printf(
        '第 %d 次请求：%s%s' . PHP_EOL,
        $i,
        $allowed ? '放行' : '限流',
        $allowed ? '' : '（建议等待 ' . $retryAfter . ' 秒）'
    );
}

/* ------------------------------------------------------------------ */
section('4. API 请求签名与重放保护');

$secret  = 'demo-shared-secret-key-please-rotate'; // 示例密钥，生产环境请从配置读取
$method  = 'POST';
$path    = '/api/v1/submit';

$apiGuard = new RequestGuard('morn_api', 3600, sys_get_temp_dir() . '/morn-guard-demo');
$ts       = null;
$signature = $apiGuard->signRequest($secret, $method, $path, $ts);
echo '签名: ' . $signature['signature'] . PHP_EOL;

var_dump($apiGuard->verifyRequestSignature(
    $secret,
    $method,
    $path,
    $signature['timestamp'],
    $signature['signature'],
    $signature['nonce']
)); // bool(true)

var_dump($apiGuard->verifyRequestSignature(
    $secret,
    $method,
    $path,
    $signature['timestamp'],
    $signature['signature'],
    $signature['nonce']
)); // bool(false) —— 同一 nonce 二次提交被拒绝

/* ------------------------------------------------------------------ */
section('5. 安全响应头');

$headers = new SecurityHeaders();
$headers->setHsts(15552000, true, false)
    ->setFrameOptions('DENY')
    ->setReferrerPolicy('strict-origin-when-cross-origin')
    ->setPermissionsPolicy([
        'geolocation' => '()',
        'camera'      => '()',
        'microphone' => '()',
    ])
    ->withDefaultWordPressCsp();

echo 'CSP nonce: ' . $headers->nonce() . PHP_EOL;
foreach ($headers->toArray() as $name => $value) {
    echo $name . ': ' . $value . PHP_EOL;
}

/* ------------------------------------------------------------------ */
section('6. Sanitizer：HTML 清洗');

$sanitizer = new Sanitizer();

$dirty = '<div class="post" onclick="alert(1)">'
    . '<script>alert(2)</script>'
    . '<a href="javascript:alert(3)">恶意链接</a>'
    . '<a href="https://example.com/ok" target="_blank">正常链接</a>'
    . '<img src="/img/a.png" alt="图" onerror="alert(4)">'
    . '<p style="color: red; behavior: url(x)">段落</p>'
    . '<iframe src="https://evil.example"></iframe>'
    . '</div>';

echo '清洗结果：' . $sanitizer->html($dirty) . PHP_EOL . PHP_EOL;

/* ------------------------------------------------------------------ */
section('7. Sanitizer：SVG 清洗（防 XSS）');

$evilSvg = '<?xml version="1.0"?>'
    . '<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">'
    . '<script>alert(1)</script>'
    . '<a xlink:href="javascript:alert(2)"><circle cx="50" cy="50" r="40" fill="red" onload="alert(3)"/></a>'
    . '<rect x="10" y="10" width="30" height="20" fill="#00ff00"/>'
    . '<foreignObject><body xmlns="http://www.w3.org/1999/xhtml">x</body></foreignObject>'
    . '</svg>';

echo $sanitizer->svg($evilSvg) . PHP_EOL . PHP_EOL;

/* ------------------------------------------------------------------ */
section('8. Sanitizer：URL / 文件名 / 路径穿越');

$urls = [
    'https://example.com/path?a=1',
    'javascript:alert(1)',
    'data:text/html;base64,PHNjcmlwdD4=',
    'data:image/png;base64,iVBORw0KGgo=',
    'mailto:someone@example.com',
    '//cdn.example.com/a.js',
];
foreach ($urls as $url) {
    printf("  %-45s => '%s'" . PHP_EOL, $url, $sanitizer->url($url));
}

echo PHP_EOL;
$filenames = ['../../etc/passwd', 'my file (1).jpg', 'shell.php', '报表 2026.csv'];
foreach ($filenames as $filename) {
    printf("  %-25s => '%s'" . PHP_EOL, $filename, $sanitizer->filename($filename, ['jpg', 'png', 'csv']));
}

echo PHP_EOL;
$base = '/var/www/uploads';
$paths = [
    'images/a.jpg',
    '../../etc/passwd',
    'a/../../b.png',
    '/var/www/other/c.jpg',
];
foreach ($paths as $path) {
    printf("  %-28s => '%s'" . PHP_EOL, $path, $sanitizer->safePath($base, $path));
}

/* ------------------------------------------------------------------ */
section('9. IpResolver：可信代理链解析');

$resolver = new IpResolver(['10.0.0.0/8', '172.16.0.0/12', '203.0.113.7']);

$cases = [
    // 客户端直连，代理头伪造应被忽略。
    [
        'label' => '直连（XFF 伪造应忽略）',
        'server' => [
            'REMOTE_ADDR'          => '198.51.100.24',
            'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
        ],
    ],
    // 可信代理，XFF 最右侧不可信地址即客户端。
    [
        'label' => 'CDN 后面（XFF 含伪造前缀）',
        'server' => [
            'REMOTE_ADDR'          => '10.0.1.5',
            'HTTP_CF_CONNECTING_IP' => '1.2.3.4',
            'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 1.2.3.4, 10.0.1.5',
        ],
    ],
    // 代理链多跳。
    [
        'label' => '多级代理链',
        'server' => [
            'REMOTE_ADDR'          => '203.0.113.7',
            'HTTP_X_FORWARDED_FOR' => '172.16.5.9, 198.51.100.77, 203.0.113.7',
        ],
    ],
];

foreach ($cases as $case) {
    printf("  %-26s => '%s'" . PHP_EOL, $case['label'], $resolver->resolve($case['server']));
}

echo PHP_EOL;
var_dump($resolver->isTrusted('10.1.2.3'));      // bool(true)
var_dump($resolver->isTrusted('203.0.113.7'));   // bool(true)
var_dump($resolver->isTrusted('8.8.8.8'));       // bool(false)
var_dump($resolver->isPrivate('192.168.1.1'));   // bool(true)
var_dump($resolver->isPrivate('93.184.216.34')); // bool(false)

echo PHP_EOL . 'GuardKit 示例运行结束。' . PHP_EOL;
