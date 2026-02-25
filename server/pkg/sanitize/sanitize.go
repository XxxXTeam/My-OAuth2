/*
 * Package sanitize 输入清洗工具
 * 功能：防止 XSS 攻击、SQL 注入等，对用户输入进行安全过滤
 *       提供字符串清洗、用户名格式校验、HTML 标签剥离等工具函数
 */
package sanitize

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

/* usernameRegex 用户名合法字符：字母、数字、下划线、连字符，3-50 字符 */
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\p{Han}\p{Hiragana}\p{Katakana}]{3,50}$`)

/* htmlTagRegex 匹配 HTML 标签 */
var htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

/* controlCharRegex 匹配不可见控制字符（保留换行和制表符） */
var controlCharRegex = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)

/*
 * String 清洗普通字符串输入
 * 功能：去除首尾空白、移除控制字符、截断过长字符串
 * @param s      - 原始字符串
 * @param maxLen - 最大长度（按 rune 计算，0 表示不限制）
 * @return string - 清洗后的字符串
 */
func String(s string, maxLen int) string {
	/* 去除首尾空白 */
	s = strings.TrimSpace(s)
	/* 移除不可见控制字符 */
	s = controlCharRegex.ReplaceAllString(s, "")
	/* 截断过长字符串 */
	if maxLen > 0 && utf8.RuneCountInString(s) > maxLen {
		runes := []rune(s)
		s = string(runes[:maxLen])
	}
	return s
}

/*
 * StripHTML 剥离所有 HTML 标签
 * 功能：移除 <script>、<img onerror> 等潜在 XSS 载体
 * @param s - 原始字符串
 * @return string - 移除 HTML 标签后的纯文本
 */
func StripHTML(s string) string {
	return htmlTagRegex.ReplaceAllString(s, "")
}

/*
 * Username 清洗并校验用户名
 * 规则：仅允许字母、数字、下划线、连字符和 CJK 字符，3-50 字符
 * @param s - 原始用户名
 * @return string - 清洗后的用户名
 * @return bool   - 是否合法
 */
func Username(s string) (string, bool) {
	s = String(s, 50)
	if !usernameRegex.MatchString(s) {
		return s, false
	}
	return s, true
}

/*
 * Email 清洗邮箱地址
 * 功能：转小写、去空白、基础格式校验
 * @param s - 原始邮箱
 * @return string - 清洗后的邮箱
 */
func Email(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	return s
}

/*
 * PlainText 清洗纯文本输入（用于简介、备注等）
 * 功能：剥离 HTML 标签、移除控制字符、截断长度
 * @param s      - 原始文本
 * @param maxLen - 最大长度
 * @return string - 安全的纯文本
 */
func PlainText(s string, maxLen int) string {
	s = StripHTML(s)
	return String(s, maxLen)
}

/*
 * URL 清洗 URL 输入
 * 功能：去空白、验证协议（仅允许 http/https）
 * @param s - 原始 URL
 * @return string - 清洗后的 URL
 * @return bool   - 是否为安全的 HTTP(S) URL
 */
func URL(s string) (string, bool) {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return s, false
	}
	/* 阻止 javascript: 协议伪装（如 http://javascript:alert(1)） */
	if strings.Contains(lower, "javascript:") {
		return s, false
	}
	return s, true
}
