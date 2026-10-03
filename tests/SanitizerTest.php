<?php
/**
 * 输入清洗器测试。
 *
 * @package MornRain\GuardKit\Tests
 */

declare(strict_types=1);

namespace MornRain\GuardKit\Tests;

use MornRain\GuardKit\Sanitizer;

/**
 * Sanitizer 测试。
 */
class SanitizerTest extends TestCase
{
    /** @var Sanitizer */
    private $s;

    protected function setUp(): void
    {
        $this->s = new Sanitizer();
    }

    /* ---------- HTML 清洗 ---------- */

    public function testHtmlStripsScriptTags(): void
    {
        $out = $this->s->html('<p>ok</p><script>alert(1)</script>');

        self::assertStringNotContains('<script', $out);
        self::assertStringNotContains('alert(1)', $out);
        self::assertStringContains('<p>ok</p>', $out);
    }

    public function testHtmlStripsEventHandlers(): void
    {
        $out = $this->s->html('<div onclick="steal()" onmouseover=\'x\'>text</div>');

        self::assertStringNotContains('onclick', $out);
        self::assertStringNotContains('onmouseover', $out);
        self::assertStringContains('text', $out);
    }

    public function testHtmlRejectsJavascriptProtocol(): void
    {
        $out = $this->s->html('<a href="javascript:alert(1)">x</a>');

        self::assertStringNotContains('javascript:', $out);
    }

    public function testHtmlEscapesAttributeValues(): void
    {
        $out = $this->s->html('<a href="https://e.com/?a=1&b=2" title=\'He said "hi"\'>x</a>');

        // 属性值中的引号必须被转义，否则可突破属性上下文
        self::assertStringNotContains('"hi"', $out);
        self::assertStringContains('&quot;', $out);
    }

    public function testHtmlEmptyInput(): void
    {
        self::assertSame('', $this->s->html(''));
        self::assertSame('', $this->s->html("   \n\t "));
    }

    public function testHtmlHandlesMultibyteAndEmoji(): void
    {
        $out = $this->s->html('<p>中文内容 🎉 テスト</p>');

        self::assertStringContains('中文内容', $out);
        self::assertStringContains('🎉', $out, '多字节与 emoji 不应被破坏');
    }

    public function testHtmlHandlesVeryLargeInput(): void
    {
        $big = str_repeat('<p>x</p><script>bad()</script>', 5000);
        $out = $this->s->html($big);

        self::assertStringNotContains('script', $out);
        self::assertTrue(strlen($out) > 0);
    }

    public function testAllowTagsOverride(): void
    {
        $sanitizer = (new Sanitizer())->allowTags(['b']);
        $out       = $sanitizer->html('<b>bold</b><i>italic</i>');

        self::assertStringContains('<b>bold</b>', $out);
        self::assertStringNotContains('<i>', $out);
    }

    public function testAllowTagsIgnoresInvalidNames(): void
    {
        $sanitizer = (new Sanitizer())->allowTags(['b', '', 'bad tag', 'onerror']);
        $out       = $sanitizer->html('<b>x</b>');

        self::assertStringContains('<b>x</b>', $out);
        self::assertStringNotContains('onerror', $out);
    }

    public function testStyleIsDroppedByDefault(): void
    {
        $out = $this->s->html('<p style="color:red">x</p>');
        self::assertStringNotContains('style', $out);
    }

    public function testStyleIsSanitizedWhenKept(): void
    {
        $out = $this->s->html('<p style="color:red;behavior:url(x);width:10px">x</p>', true);

        self::assertStringContains('color', $out);
        self::assertStringNotContains('behavior', $out, '危险 CSS 属性必须被剔除');
    }

    /* ---------- SVG 清洗 ---------- */

    public function testSvgRemovesScriptAndDoctype(): void
    {
        $svg = '<?xml version="1.0"?><!DOCTYPE svg><svg><script>alert(1)</script><rect/></svg>';
        $out = $this->s->svg($svg);

        self::assertStringNotContains('script', $out);
        self::assertStringNotContains('DOCTYPE', $out);
        self::assertStringContains('<rect', $out);
    }

    public function testSvgRemovesEventHandlers(): void
    {
        $out = $this->s->svg('<svg onload="alert(1)"><rect onclick="x"/></svg>');

        self::assertStringNotContains('onload', $out);
        self::assertStringNotContains('onclick', $out);
    }

    public function testSvgRemovesExternalReferences(): void
    {
        $out = $this->s->svg('<svg><rect fill="url(https://evil.com/x)"/></svg>');
        self::assertStringNotContains('evil.com', $out);
    }

    public function testSvgEmptyInput(): void
    {
        self::assertSame('', $this->s->svg(''));
    }

    /* ---------- URL 清洗 ---------- */

    public function testUrlAllowsSafeSchemes(): void
    {
        self::assertSame('https://e.com/a', $this->s->url('https://e.com/a'));
        self::assertSame('http://e.com', $this->s->url('http://e.com'));
        self::assertSame('mailto:a@b.com', $this->s->url('mailto:a@b.com'));
        self::assertSame('tel:+123', $this->s->url('tel:+123'));
    }

    public function testUrlRejectsDangerousSchemes(): void
    {
        foreach (['javascript:alert(1)', 'vbscript:x', 'file:///etc/passwd', 'data:text/html,<script>'] as $bad) {
            self::assertSame('', $this->s->url($bad), "应拒绝：{$bad}");
        }
    }

    public function testUrlBlocksControlCharacterObfuscation(): void
    {
        // "java\tscript:" 这类绕过必须失效
        self::assertSame('', $this->s->url("java\tscript:alert(1)"));
        self::assertSame('', $this->s->url("java\x00script:alert(1)"));
        self::assertSame('', $this->s->url(" javascript:alert(1) "));
    }

    public function testUrlAllowsDataImage(): void
    {
        $png = 'data:image/png;base64,iVBORw0KGgo=';
        self::assertSame($png, $this->s->url($png));
        // data:image/svg+xml 可携带脚本，必须拒绝
        self::assertSame('', $this->s->url('data:image/svg+xml;base64,PHN2Zz48L3N2Zz4='));
    }

    public function testUrlProtocolRelativeBecomesHttps(): void
    {
        self::assertSame('https://e.com/x', $this->s->url('//e.com/x'));
    }

    public function testUrlRelativePath(): void
    {
        self::assertSame('/a/b', $this->s->url('/a/b'));
        self::assertSame('', $this->s->url(''));
    }

    /* ---------- 文件名 ---------- */

    public function testFilenameStripsTraversalAndSlashes(): void
    {
        self::assertSame('etcpasswd.php', $this->s->filename('../../etc/passwd.php', ['.php']));
        self::assertSame('ab.c.php', $this->s->filename('a/b/../../c.php', ['.php']));
    }

    public function testFilenameRejectsNullByte(): void
    {
        // 空字节截断曾可绕过扩展名校验
        $out = $this->s->filename("evil.php\x00.jpg", ['.php']);
        self::assertStringNotContains("\x00", $out);
    }

    public function testFilenameRejectsWindowsReservedNames(): void
    {
        foreach (['NUL.php', 'con.txt', 'AUX', 'COM1.php'] as $bad) {
            self::assertSame('file', $this->s->filename($bad), "应拒绝 Windows 保留名：{$bad}");
        }
        self::assertSame('normal.php', $this->s->filename('normal.php', ['.php']));
    }

    public function testFilenameEnforcesExtensionWhitelist(): void
    {
        self::assertSame('file', $this->s->filename('shell.php', ['.jpg', '.png']));
        self::assertSame('photo.png', $this->s->filename('photo.png', ['.jpg', '.png']));
        self::assertSame('file', $this->s->filename('noext', ['.png']));
    }

    public function testFilenameFallbackForEmptyInput(): void
    {
        self::assertSame('file', $this->s->filename(''));
        self::assertSame('file', $this->s->filename('..'));
        self::assertSame('file', $this->s->filename('.'));
        self::assertSame('file', $this->s->filename('...'));
    }

    public function testFilenameTruncatesLongNames(): void
    {
        $out = $this->s->filename(str_repeat('a', 500) . '.php', ['.php']);
        self::assertTrue(strlen($out) <= 120, '超长文件名必须被截断');
        self::assertStringContains('.php', $out, '截断后应保留扩展名');
    }

    /* ---------- 路径穿越 ---------- */

    public function testSafePathAllowsInsideBase(): void
    {
        self::assertSame('/site/uploads/a.txt', $this->s->safePath('/site/uploads', 'a.txt'));
        self::assertSame('/site/uploads/sub/a.txt', $this->s->safePath('/site/uploads', 'sub/a.txt'));
    }

    public function testSafePathBlocksTraversal(): void
    {
        self::assertSame('', $this->s->safePath('/site/uploads', '../../etc/passwd'));
        self::assertSame('', $this->s->safePath('/site/uploads', '/etc/passwd'));
        self::assertSame('', $this->s->safePath('/site/uploads', '../uploads-secret/x.txt'));
    }

    public function testSafePathBlocksNullByte(): void
    {
        self::assertSame('', $this->s->safePath('/site', "a.txt\x00.php"));
    }

    public function testSafePathHandlesWindowsSeparators(): void
    {
        // Windows 风格的 ..\..\ 必须同样被拦截
        self::assertSame('', $this->s->safePath('C:/site/uploads', '..\\..\\secret.txt'));
        self::assertSame('C:/site/uploads/a.txt', $this->s->safePath('C:\\site\\uploads', 'a.txt'));
    }

    public function testSafePathRelativeMode(): void
    {
        self::assertSame('sub/a.txt', $this->s->safePath('/site/uploads', 'sub/a.txt', true));
        self::assertSame('', $this->s->safePath('/site/uploads', '../x', true));
    }

    public function testSafePathEmptyInputs(): void
    {
        self::assertSame('', $this->s->safePath('', 'a.txt'));
        self::assertSame('', $this->s->safePath('/site', ''));
    }

    /* ---------- 标量清洗 ---------- */

    public function testIdentifierStripsNonAlnum(): void
    {
        self::assertSame('users', $this->s->identifier('users'));
        // 空格也被剔除，只剩字母数字
        self::assertSame('usersDROPTABLE', $this->s->identifier('users;DROP TABLE'));
        self::assertSame('', $this->s->identifier('!!!'));
    }

    public function testTextStripsTagsAndControls(): void
    {
        self::assertSame('hello', $this->s->text('<b>hello</b>'));
        self::assertSame('ab', $this->s->text("a\x00\x07b"));
    }

    public function testTextPreservesMultibyte(): void
    {
        self::assertSame('中文测试', $this->s->text('<p>中文测试</p>'));
        self::assertSame('中文 🎉', $this->s->text('中文 🎉'));
    }

    public function testIntegerAndFloatClamping(): void
    {
        self::assertSame(5, $this->s->integer('5'));
        self::assertSame(0, $this->s->integer('abc'), '非数字应归零');
        self::assertSame(10, $this->s->integer(999, 1, 10));
        self::assertSame(1, $this->s->integer(-5, 1, 10));
        self::assertSame(1.5, $this->s->float('1.5'));
        self::assertSame(0.0, $this->s->float('x'));
        self::assertEqualsWithDelta(3.0, $this->s->float(99.0, 0.0, 3.0), 0.001);
    }

    public function testIntegerHandlesArrayInput(): void
    {
        // 数组不应触发致命错误，应安全归零
        self::assertSame(0, $this->s->integer(['x']));
        self::assertSame(0.0, $this->s->float(['x']));
    }

    public function testEmailValidation(): void
    {
        self::assertSame('a@b.com', $this->s->email('a@b.com'));
        self::assertSame('', $this->s->email('not-an-email'));
        self::assertSame('', $this->s->email('a@b'));
        self::assertSame('', $this->s->email(''));
    }

    /* ---------- 便捷函数 ---------- */

    public function testHelperFunctionsWork(): void
    {
        self::assertSame('', \MornRain\GuardKit\morn_sanitize_html('<script>x</script>'));
        self::assertSame('', \MornRain\GuardKit\morn_sanitize_url('javascript:x'));
        self::assertSame('<b>b</b>', \MornRain\GuardKit\morn_sanitize_html('<b>b</b>'));
        self::assertSame('', \MornRain\GuardKit\morn_safe_path('/base', '../x'));
        self::assertInstanceOf(
            \MornRain\GuardKit\SecurityHeaders::class,
            \MornRain\GuardKit\morn_security_headers()
        );
    }
}