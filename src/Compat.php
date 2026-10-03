<?php
/**
 * 环境兼容垫片。
 *
 * 本库既可在 WordPress 中运行，也可在任意 PHP 7.4+ 独立环境运行。
 * 涉及输出转义的少量 WordPress 函数（esc_attr / esc_html）在此统一封装：
 * WordPress 存在时优先复用其实现（保证与主题规范一致），
 * 不存在时退回到等价的 htmlspecialchars 语义。
 *
 * @package MornRain\GuardKit
 */

declare(strict_types=1);

namespace MornRain\GuardKit;

/**
 * 兼容辅助类。
 */
final class Compat
{
    /**
     * 转义 HTML 属性值。
     */
    public static function attr(string $value): string
    {
        if (function_exists('esc_attr')) {
            return (string) esc_attr($value);
        }

        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8', false);
    }

    /**
     * 转义 HTML 文本节点。
     */
    public static function html(string $value): string
    {
        if (function_exists('esc_html')) {
            return (string) esc_html($value);
        }

        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8', false);
    }
}
