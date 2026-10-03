<?php
/**
 * 输入清洗工具。
 *
 * 提供 HTML / SVG 白名单清洗、URL 协议白名单、文件名白名单、
 * 路径穿越防护以及 SQL 标识符白名单等功能。所有方法均为纯函数，
 * 不依赖 WordPress，可在任意 PHP 7.4+ 环境中使用。
 *
 * @package MornRain\GuardKit
 */

declare(strict_types=1);

namespace MornRain\GuardKit;

use InvalidArgumentException;

/**
 * 清洗器。
 */
class Sanitizer
{
    /**
     * Windows 保留设备名。
     *
     * 这些名称在 Windows 上被操作系统截获，NUL.php 之类的文件无法正常删除，
     * 也可用于绕过基于扩展名的上传校验，因此在文件名清洗时必须拒绝。
     *
     * @var array<int,string>
     */
    protected const WINDOWS_RESERVED = [
        'con', 'prn', 'aux', 'nul',
        'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
        'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
    ];

    /** @var array<int,string> HTML 允许的标签 */
    protected $allowedTags = [
        'a', 'abbr', 'b', 'blockquote', 'br', 'caption', 'cite', 'code', 'col', 'colgroup',
        'dd', 'del', 'div', 'dl', 'dt', 'em', 'figcaption', 'figure', 'h1', 'h2', 'h3',
        'h4', 'h5', 'h6', 'hr', 'i', 'img', 'ins', 'kbd', 'li', 'mark', 'ol', 'p', 'pre',
        'q', 's', 'samp', 'small', 'span', 'strong', 'sub', 'sup', 'table', 'tbody', 'td',
        'tfoot', 'th', 'thead', 'time', 'tr', 'u', 'ul', 'var', 'wbr',
    ];

    /** @var array<string,array<int,string>> 允许的标签属性 */
    protected $allowedAttributes = [
        'a'          => ['href', 'title', 'target', 'rel'],
        'img'        => ['src', 'alt', 'width', 'height', 'loading', 'decoding', 'srcset', 'sizes'],
        'td'         => ['colspan', 'rowspan'],
        'th'         => ['colspan', 'rowspan', 'scope'],
        'col'        => ['span'],
        'colgroup'   => ['span'],
        'time'       => ['datetime'],
        'ol'         => ['start', 'reversed', 'type'],
        'blockquote' => ['cite'],
        'q'          => ['cite'],
        'del'        => ['cite', 'datetime'],
        'ins'        => ['cite', 'datetime'],
    ];

    /** @var array<int,string> 全局允许的属性 */
    protected $globalAttributes = ['class', 'id', 'style', 'title', 'dir', 'lang'];

    /** @var array<int,string> URL 允许的协议 */
    protected $allowedProtocols = ['http', 'https', 'mailto', 'tel'];

    /**
     * 覆盖 HTML 标签白名单。
     *
     * @param array<int,string> $tags
     */
    public function allowTags(array $tags): self
    {
        $normalized = [];
        foreach ($tags as $tag) {
            $tag = strtolower(trim((string) $tag));
            if ($tag !== '' && preg_match('/^[a-z][a-z0-9-]*$/', $tag) === 1) {
                $normalized[] = $tag;
            }
        }
        $this->allowedTags = array_values(array_unique($normalized));

        return $this;
    }

    /**
     * 追加允许的标签。
     *
     * @param array<int,string> $tags
     */
    public function addTags(array $tags): self
    {
        return $this->allowTags(array_merge($this->allowedTags, $tags));
    }

    /**
     * 覆盖属性白名单。
     *
     * @param array<string,array<int,string>> $map
     */
    public function allowAttributes(array $map): self
    {
        $normalized = [];
        foreach ($map as $tag => $attrs) {
            $tag = strtolower(trim((string) $tag));
            if ($tag === '' || !is_array($attrs)) {
                continue;
            }
            $list = [];
            foreach ($attrs as $attr) {
                $attr = strtolower(trim((string) $attr));
                if ($attr !== '' && preg_match('/^[a-z][a-z0-9-]*$/', $attr) === 1) {
                    $list[] = $attr;
                }
            }
            if ($list !== []) {
                $normalized[$tag] = $list;
            }
        }
        $this->allowedAttributes = $normalized;

        return $this;
    }

    /**
     * 追加全局允许属性。
     *
     * @param array<int,string> $attrs
     */
    public function addGlobalAttributes(array $attrs): self
    {
        foreach ($attrs as $attr) {
            $attr = strtolower(trim((string) $attr));
            if ($attr !== '' && preg_match('/^[a-z][a-z0-9-]*$/', $attr) === 1) {
                $this->globalAttributes[] = $attr;
            }
        }
        $this->globalAttributes = array_values(array_unique($this->globalAttributes));

        return $this;
    }

    /**
     * 清洗 HTML：仅保留白名单标签与属性，移除脚本、事件属性与危险协议。
     *
     * 若存在 WordPress 环境则复用 wp_kses 的成熟实现，否则使用内置解析器。
     *
     * @param string $html 待清洗的 HTML。
     * @param bool   $keepStyle 是否保留经过安全化处理的 style 属性。
     */
    public function html(string $html, bool $keepStyle = false): string
    {
        if (trim($html) === '') {
            return '';
        }

        if (function_exists('wp_kses')) {
            $allowed = $this->buildAllowedHtml();
            $result  = (string) wp_kses($html, $allowed, ['style' => $keepStyle]);

            return $this->neutralizeScripts($result);
        }

        return $this->internalHtmlFilter($html, $keepStyle);
    }

    /**
     * 清洗 SVG：防 XSS。
     *
     * 仅允许静态绘图标签与安全属性，剥离 <script>、事件属性、
     * <foreignObject>、外部引用（use xlink:href 到站外）等危险构造。
     *
     * @param string $svg 原始 SVG 字符串。
     */
    public function svg(string $svg): string
    {
        if (trim($svg) === '') {
            return '';
        }

        // 移除 XML 声明与 DOCTYPE，避免实体注入。
        $svg = preg_replace('/<\?xml[^>]*\?>/i', '', $svg) ?? $svg;
        $svg = preg_replace('/<!DOCTYPE[^>]*>/i', '', $svg) ?? $svg;
        // 移除 CDATA 段。
        $svg = preg_replace('#<!\[CDATA\[.*?\]\]>#s', '', $svg) ?? $svg;

        $allowedTags = [
            'svg', 'g', 'defs', 'symbol', 'use', 'title', 'desc', 'path', 'rect', 'circle',
            'ellipse', 'line', 'polyline', 'polygon', 'text', 'tspan', 'linearGradient',
            'radialGradient', 'stop', 'clipPath', 'mask', 'pattern', 'marker',
        ];

        $allowedAttrs = [
            'viewbox', 'xmlns', 'xmlns:xlink', 'version', 'width', 'height', 'fill', 'stroke',
            'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'stroke-dasharray',
            'stroke-dashoffset', 'stroke-opacity', 'fill-opacity', 'opacity', 'transform',
            'd', 'cx', 'cy', 'r', 'rx', 'ry', 'x', 'y', 'x1', 'x2', 'y1', 'y2', 'points',
            'offset', 'stop-color', 'stop-opacity', 'gradientunits', 'gradienttransform',
            'id', 'class', 'preserveaspectratio', 'font-family', 'font-size', 'font-weight',
            'text-anchor', 'dominant-baseline', 'clip-path', 'mask', 'marker-end',
            'marker-start', 'fill-rule', 'vector-effect', 'shape-rendering',
        ];

        // 危险元素直接整段删除。
        $svg = preg_replace('#<\s*(script|foreignObject|iframe|animate|set|handler|audio|video)\b.*?<\s*/\s*\1\s*>#is', '', $svg) ?? $svg;
        $svg = preg_replace('#<\s*(script|foreignObject|iframe|animate|set|handler)\b[^>]*/?>#is', '', $svg) ?? $svg;

        $result = preg_replace_callback(
            '#<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9:_.-]*)([^>]*?)(/?)\s*>#s',
            function (array $m) use ($allowedTags, $allowedAttrs): string {
                $closing = $m[1] === '/';
                $tag     = strtolower($m[2]);
                $attrs   = $m[3];
                $selfEnd = $m[4] === '/';

                if (!in_array($tag, $allowedTags, true)) {
                    return '';
                }

                if ($closing) {
                    return '</' . $tag . '>';
                }

                $safeAttrs = $this->filterSvgAttributes($attrs, $allowedAttrs);

                return '<' . $tag . $safeAttrs . ($selfEnd ? ' /' : '') . '>';
            },
            $svg
        );

        $result = $result ?? '';
        // 任何位置出现 </script 都可能截断 HTML 解析上下文。
        $result = str_ireplace(['</script', '<script'], ['', ''], $result);

        return trim($result);
    }

    /**
     * 清洗 URL：仅允许白名单协议，过滤 javascript: / data: 等危险 scheme。
     *
     * @param string $url 待清洗 URL。
     */
    public function url(string $url): string
    {
        $url = trim($url);
        if ($url === '') {
            return '';
        }

        // 去掉控制字符与空白，阻止 "java\tscript:" 绕过。
        $normalized = preg_replace('/[\x00-\x20\x7F]+/', '', $url) ?? $url;
        if ($normalized === '') {
            return '';
        }

        // 协议相对地址 //example.com 视为 https 处理。
        if (strpos($normalized, '//') === 0) {
            return 'https:' . $normalized;
        }

        if (!preg_match('#^([a-zA-Z][a-zA-Z0-9+.\-]*):#', $normalized, $m)) {
            // 相对路径或锚点。
            if (preg_match('#^[a-zA-Z0-9/_\-.~%?&=:@\+]+$#', $normalized) === 1 && strpos($normalized, ':') === false) {
                return $normalized;
            }

            return '';
        }

        $scheme = strtolower($m[1]);

        // data: 仅允许内联位图类型，且必须校验完整格式（阻断 data:text/html 等 XSS 载荷）。
        // 注意：svg+xml **不可**放行 —— SVG 是可执行容器，
        // data:image/svg+xml 能在 img/src、iframe 等上下文中携带脚本，
        // 属于典型的 XSS 绕过路径。
        if ($scheme === 'data') {
            return preg_match('#^data:image/(png|gif|jpe?g|webp|avif);base64,[A-Za-z0-9+/=]+$#i', $normalized) === 1
                ? $normalized
                : '';
        }

        if (!in_array($scheme, $this->allowedProtocols, true)) {
            return '';
        }

        return $url;
    }

    /**
     * 清洗文件名：仅保留安全字符，防止 ../ 与空字节。
     *
     * @param string      $filename   原始文件名。
     * @param array<int,string> $allowedExtensions 允许的扩展名（含点，小写）。
     * @param string      $fallback   非法时的替代名。
     */
    public function filename(string $filename, array $allowedExtensions = [], string $fallback = 'file'): string
    {
        $filename = str_replace(["\0", "\\", '/'], '', $filename);
        $filename = trim($filename);
        if ($filename === '' || $filename === '.' || $filename === '..') {
            return $fallback;
        }

        // 移除 .. 序列。
        $filename = preg_replace('/\.\.+/', '.', $filename) ?? $filename;
        $filename = preg_replace('/[^A-Za-z0-9._\-]/', '_', $filename) ?? $filename;
        $filename = ltrim($filename, '.-_');

        if ($filename === '') {
            return $fallback;
        }

        if ($allowedExtensions !== []) {
            $ext = strtolower((string) pathinfo($filename, PATHINFO_EXTENSION));
            if ($ext === '') {
                return $fallback;
            }
            $dotExt = '.' . $ext;
            $ok     = false;
            foreach ($allowedExtensions as $allowed) {
                $allowed = '.' . strtolower(ltrim(trim((string) $allowed), '.'));
                if ($dotExt === $allowed) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return $fallback;
            }
        }

        // 限制长度，保留扩展名。
        if (strlen($filename) > 120) {
            $ext      = (string) pathinfo($filename, PATHINFO_EXTENSION);
            $base     = (string) pathinfo($filename, PATHINFO_FILENAME);
            $keep     = $ext === '' ? '' : '.' . $ext;
            $filename = substr($base, 0, 120 - strlen($keep)) . $keep;
        }

        // Windows 保留设备名：NUL.php / con.txt 等在 Windows 上不可安全操作。
        // 注意要连扩展名一起去掉后再比对，因为系统只看主名。
        $stem = strtolower((string) pathinfo($filename, PATHINFO_FILENAME));
        if (in_array($stem, self::WINDOWS_RESERVED, true)) {
            return $fallback;
        }

        return $filename;
    }

    /**
     * 路径穿越防护：确保 $path 位于 $baseDir 之内。
     *
     * @param string $baseDir  基准目录。
     * @param string $path     待校验路径。
     * @param bool   $allowRelative 是否允许返回相对基准目录的路径。
     * @return string 规范化后的安全路径；越界时返回空串。
     */
    public function safePath(string $baseDir, string $path, bool $allowRelative = false): string
    {
        $baseDir = rtrim($this->normalizeSeparators($baseDir), '/');
        if ($baseDir === '' || $path === '') {
            return '';
        }

        $path = $this->normalizeSeparators($path);
        if (strpos($path, "\0") !== false) {
            return '';
        }

        // 相对路径拼接基准目录，绝对路径直接使用。
        $target = (strpos($path, '/') === 0) ? $path : $baseDir . '/' . $path;
        // 基准目录本身可能就是绝对路径，因此以 $target 判断。
        $isAbsolute = strpos($target, '/') === 0;

        // 不做 realpath（目标文件可能尚不存在），改为逐段消解 . 与 ..
        $segments = [];
        foreach (explode('/', $target) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }
        $resolved = implode('/', $segments);

        // 还原被消解掉的前导斜杠，保证与 $baseDir 前缀可比。
        if ($isAbsolute) {
            $resolved = '/' . $resolved;
        }

        if ($resolved !== $baseDir && strpos($resolved, $baseDir . '/') !== 0) {
            return '';
        }

        if ($allowRelative) {
            $relative = ltrim(substr($resolved, strlen($baseDir)), '/');

            return $relative;
        }

        return $resolved;
    }

    /**
     * 清洗 SQL 标识符（表名/列名），仅允许字母数字与下划线。
     */
    public function identifier(string $identifier): string
    {
        $identifier = preg_replace('/[^A-Za-z0-9_]/', '', $identifier) ?? '';

        return $identifier;
    }

    /**
     * 清洗纯文本：去除标签与不可见控制字符。
     */
    public function text(string $text, bool $keepNewlines = true): string
    {
        $text = strip_tags($text);
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $pattern = $keepNewlines ? '/[^\P{C}\n\t\r]/u' : '/[^\P{C}]/u';
        $text = preg_replace($pattern, '', $text) ?? $text;

        return trim($text);
    }

    /**
     * 清洗整数与浮点数。
     */
    public function integer($value, int $min = PHP_INT_MIN, int $max = PHP_INT_MAX): int
    {
        $int = is_numeric($value) ? (int) $value : 0;

        return max($min, min($max, $int));
    }

    /**
     * 清洗浮点数。
     */
    public function float($value, float $min = -PHP_FLOAT_MAX, float $max = PHP_FLOAT_MAX): float
    {
        $float = is_numeric($value) ? (float) $value : 0.0;

        return max($min, min($max, $float));
    }

    /**
     * 清洗邮箱地址。
     */
    public function email(string $email): string
    {
        $email = trim($email);
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return '';
        }

        return $email;
    }

    /**
     * 生成 wp_kses 需要的白名单结构。
     *
     * @return array<string,array<string,bool>>
     */
    protected function buildAllowedHtml(): array
    {
        $map = [];
        foreach ($this->allowedTags as $tag) {
            $attrs = array_merge($this->globalAttributes, $this->allowedAttributes[$tag] ?? []);
            foreach ($attrs as $attr) {
                $map[$tag][$attr] = true;
            }
        }

        return $map;
    }

    /**
     * 移除残留的可执行片段。
     */
    protected function neutralizeScripts(string $html): string
    {
        $html = preg_replace('#<\s*(script|style|iframe|object|embed|applet|form)\b.*?<\s*/\s*\1\s*>#is', '', $html) ?? $html;
        $html = preg_replace('#<\s*(script|style|iframe|object|embed|applet|form)\b[^>]*/?>#is', '', $html) ?? $html;
        // 移除事件属性与 style 中的表达式。
        $html = preg_replace('/\son[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $html) ?? $html;
        $html = preg_replace('/(href|src|xlink:href|formaction|action)\s*=\s*("|\')\s*(javascript|vbscript|data)\s*:[^"\']*\2/i', '', $html) ?? $html;

        return $html;
    }

    /**
     * 内置 HTML 过滤器（无 WordPress 时使用）。
     */
    protected function internalHtmlFilter(string $html, bool $keepStyle): string
    {
        // 先移除会执行脚本的整块内容。
        $html = $this->neutralizeScripts($html);

        $result = preg_replace_callback(
            // 引号优先匹配：`class="a>b"` 中值里的 `>` 若被当作标签结束，
            // 会让剩余内容作为纯文本泄漏到输出中（并可能携带可执行片段）。
            '#<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9]*)((?:"[^"]*"|\'[^\']*\'|[^>"\'])*)(/?)\s*>#s',
            function (array $m) use ($keepStyle): string {
                $closing = $m[1] === '/';
                $tag     = strtolower($m[2]);
                $attrs   = $m[3];
                $selfEnd = $m[4] === '/';

                if ($closing) {
                    return in_array($tag, $this->allowedTags, true) ? '</' . $tag . '>' : '';
                }
                if (!in_array($tag, $this->allowedTags, true)) {
                    // 未知标签保留其文本内容但丢弃标签本身。
                    return '';
                }

                return '<' . $tag . $this->filterHtmlAttributes($tag, $attrs, $keepStyle) . ($selfEnd ? ' /' : '') . '>';
            },
            $html
        );

        return trim($result ?? '');
    }

    /**
     * 过滤普通 HTML 标签的属性。
     */
    protected function filterHtmlAttributes(string $tag, string $attrs, bool $keepStyle): string
    {
        $allowed = array_merge($this->globalAttributes, $this->allowedAttributes[$tag] ?? []);
        if (!$keepStyle) {
            $allowed = array_values(array_diff($allowed, ['style']));
        }

        $out = '';
        if (preg_match_all('#([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))#s', $attrs, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $name = strtolower($match[1]);
                if (!in_array($name, $allowed, true)) {
                    continue;
                }
                $value = $match[3] ?? '';
                if ($value === '' && isset($match[4])) {
                    $value = $match[4];
                }
                if ($value === '' && isset($match[5])) {
                    $value = $match[5];
                }
                $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');

                if (in_array($name, ['href', 'src', 'cite'], true)) {
                    $safe = $this->url($value);
                    if ($safe === '') {
                        continue;
                    }
                    $value = $safe;
                }

                if ($name === 'style') {
                    $value = $this->safeStyle($value);
                    if ($value === '') {
                        continue;
                    }
                }

                if (in_array($name, ['width', 'height', 'colspan', 'rowspan', 'span', 'start'], true)) {
                    if (preg_match('/^\d{1,5}$/', $value) !== 1) {
                        continue;
                    }
                }

                $out .= ' ' . $name . '="' . Compat::attr($value) . '"';
            }
        }

        return $out;
    }

    /**
     * 过滤 SVG 属性。
     *
     * @param array<int,string> $allowed
     */
    protected function filterSvgAttributes(string $attrs, array $allowed): string
    {
        $out = '';
        if (preg_match_all('#([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))#s', $attrs, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $name = strtolower($match[1]);
                if (!in_array($name, $allowed, true)) {
                    continue;
                }
                $value = $match[3] ?? '';
                if ($value === '' && isset($match[4])) {
                    $value = $match[4];
                }
                if ($value === '' && isset($match[5])) {
                    $value = $match[5];
                }
                $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');

                // 禁止 url() 引用外部资源与表达式。
                if (preg_match('/(javascript:|expression\s*\(|@import|data:text\/html)/i', $value) === 1) {
                    continue;
                }
                // fill/stroke 允许 url(#id) 形式的站内引用。
                if (in_array($name, ['fill', 'stroke', 'clip-path', 'mask', 'filter', 'marker-end', 'marker-start'], true)
                    && preg_match('/url\s*\(/i', $value) === 1
                    && preg_match('/url\s*\(\s*[\'"]?#[\w-]+[\'"]?\s*\)/i', $value) !== 1
                ) {
                    continue;
                }

                $out .= ' ' . $name . '="' . Compat::attr($value) . '"';
            }
        }

        return $out;
    }

    /**
     * 安全化 style 属性：只保留安全的属性声明。
     */
    protected function safeStyle(string $style): string
    {
        $safeProps = [
            'color', 'background-color', 'font-size', 'font-weight', 'font-style', 'font-family',
            'text-align', 'text-decoration', 'text-indent', 'line-height', 'letter-spacing',
            'margin', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
            'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
            'width', 'max-width', 'height', 'max-height', 'display', 'border',
            'border-radius', 'opacity', 'vertical-align', 'list-style-type',
        ];

        $declarations = [];
        foreach (explode(';', $style) as $declaration) {
            if (strpos($declaration, ':') === false) {
                continue;
            }
            [$prop, $value] = array_map('trim', explode(':', $declaration, 2));
            $prop = strtolower($prop);
            if (!in_array($prop, $safeProps, true)) {
                continue;
            }
            if (preg_match('/[<>{}()@;\\\\]|expression|javascript:|url\s*\(/i', $value) === 1) {
                continue;
            }
            $declarations[] = $prop . ': ' . $value;
        }

        return implode('; ', $declarations);
    }

    /**
     * 统一路径分隔符为正斜杠。
     */
    protected function normalizeSeparators(string $path): string
    {
        return str_replace('\\', '/', $path);
    }
}
