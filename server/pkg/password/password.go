/*
 * Package password 密码工具包
 * 功能：提供 bcrypt 哈希、密码校验、强度检测和随机密码生成
 */
package password

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

/* cost bcrypt 哈希代价因子（12 约 250ms/次） */
const cost = 12

/*
 * bcrypt 最大输入长度为 72 字节
 * 超过此长度的密码会被静默截断，导致安全问题
 */
const maxPasswordLength = 72

var (
	ErrPasswordTooLong   = errors.New("password: exceeds maximum length of 72 bytes")
	ErrPasswordTooShort  = errors.New("password: must be at least 8 characters")
	ErrPasswordWeak      = errors.New("password: must contain uppercase, lowercase, digit, and special character")
	ErrPasswordCommon    = errors.New("password: too common, please choose a more unique password")
	ErrPasswordSameAsOld = errors.New("password: new password must be different from current password")
)

/*
 * commonPasswords 常见弱密码黑名单（Top 50 最常见密码）
 * 用于阻止用户使用已知泄露或极弱的密码
 */
var commonPasswords = map[string]bool{
	"password": true, "12345678": true, "123456789": true, "1234567890": true,
	"qwerty123": true, "abc12345": true, "password1": true, "iloveyou": true,
	"sunshine1": true, "princess1": true, "football1": true, "charlie1": true,
	"access14": true, "shadow12": true, "master12": true, "michael1": true,
	"superman1": true, "dragon12": true, "monkey123": true, "qwerty12": true,
	"letmein1": true, "trustno1": true, "welcome1": true, "admin123": true,
	"passw0rd": true, "p@ssw0rd": true, "p@ssword": true, "password123": true,
	"changeme": true, "12345678a": true, "1q2w3e4r": true, "qwertyui": true,
	"asdfghjk": true, "zxcvbnm1": true, "abcd1234": true, "11111111": true,
	"00000000": true, "88888888": true, "qwer1234": true, "1234qwer": true,
}

/*
 * StrengthResult 密码强度检测结果
 * 功能：返回密码强度等级和具体检测信息
 */
type StrengthResult struct {
	Score       int    `json:"score"`       /* 0-4，0=极弱 4=极强 */
	Level       string `json:"level"`       /* weak, fair, good, strong, very_strong */
	HasUpper    bool   `json:"has_upper"`   /* 包含大写字母 */
	HasLower    bool   `json:"has_lower"`   /* 包含小写字母 */
	HasDigit    bool   `json:"has_digit"`   /* 包含数字 */
	HasSpecial  bool   `json:"has_special"` /* 包含特殊字符 */
	LengthValid bool   `json:"length_valid"`
}

/*
 * CheckStrength 检测密码强度
 * @param password - 明文密码
 * @return StrengthResult - 强度检测结果
 */
func CheckStrength(password string) StrengthResult {
	result := StrengthResult{}
	result.LengthValid = len(password) >= 8

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			result.HasUpper = true
		case unicode.IsLower(ch):
			result.HasLower = true
		case unicode.IsDigit(ch):
			result.HasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			result.HasSpecial = true
		}
	}

	/* 计算强度分数 */
	score := 0
	if result.LengthValid {
		score++
	}
	if result.HasUpper && result.HasLower {
		score++
	}
	if result.HasDigit {
		score++
	}
	if result.HasSpecial {
		score++
	}
	if len(password) >= 12 {
		score++
	}
	if score > 4 {
		score = 4
	}

	result.Score = score
	levels := []string{"weak", "fair", "good", "strong", "very_strong"}
	result.Level = levels[score]

	return result
}

/*
 * ValidateStrength 校验密码是否满足最低强度要求
 * @param password - 明文密码
 * @return error   - 不满足要求时返回错误
 */
func ValidateStrength(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	if len(password) > maxPasswordLength {
		return ErrPasswordTooLong
	}
	/* 检查常见弱密码黑名单 */
	if commonPasswords[strings.ToLower(password)] {
		return ErrPasswordCommon
	}
	return nil
}

/*
 * ValidateChange 校验密码变更：新密码强度 + 不能与旧密码相同
 * @param newPassword - 新密码明文
 * @param oldHash     - 旧密码 bcrypt 哈希
 * @return error      - 不满足要求时返回错误
 */
func ValidateChange(newPassword, oldHash string) error {
	if err := ValidateStrength(newPassword); err != nil {
		return err
	}
	if Verify(newPassword, oldHash) {
		return ErrPasswordSameAsOld
	}
	return nil
}

/*
 * GenerateRandom 生成指定长度的随机密码
 * @param length - 密码长度
 * @return string - 随机密码（Base64 URL 编码）
 */
func GenerateRandom(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

/*
 * Hash 使用 bcrypt 生成密码哈希
 * @param password - 明文密码
 * @return string  - bcrypt 哈希字符串
 * 安全：校验密码长度不超过 bcrypt 72 字节限制
 */
func Hash(password string) (string, error) {
	if len(password) > maxPasswordLength {
		return "", ErrPasswordTooLong
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

/*
 * Verify 校验密码与哈希是否匹配
 * @param password - 明文密码
 * @param hash     - bcrypt 哈希
 * @return bool    - 匹配返回 true
 */
func Verify(password, hash string) bool {
	if len(password) > maxPasswordLength {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/*
 * NeedsRehash 检测密码哈希是否需要重新生成
 * 功能：当 bcrypt cost 升级后，旧哈希使用较低 cost，需在用户下次登录时透明升级
 * @param hash - 当前存储的 bcrypt 哈希
 * @return bool - 需要重新哈希返回 true
 */
func NeedsRehash(hash string) bool {
	hashCost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true /* 无法解析 cost，建议重新哈希 */
	}
	return hashCost < cost
}
