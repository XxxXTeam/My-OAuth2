/*
 * Package password 密码工具包
 * 功能：提供 bcrypt 哈希、密码校验和随机密码生成
 */
package password

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

/* cost bcrypt 哈希代价因子（12 约 250ms/次） */
const cost = 12

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
 */
func Hash(password string) (string, error) {
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
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
