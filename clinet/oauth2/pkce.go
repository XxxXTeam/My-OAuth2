package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

/*
 * PKCE Proof Key for Code Exchange (RFC 7636) 结构
 * 功能：存储 code_verifier 和 code_challenge，增强公开客户端的授权码安全性
 */
type PKCE struct {
	CodeVerifier  string
	CodeChallenge string
	Method        string
}

/*
 * GeneratePKCE 生成新的 PKCE code_verifier 和 code_challenge
 * 功能：使用 crypto/rand 生成 32 字节随机 verifier，SHA256 哈希后 Base64 URL 编码为 challenge
 * @return *PKCE - 包含 verifier、challenge 和方法 (S256)
 */
func GeneratePKCE() (*PKCE, error) {
	// Generate a random code verifier (43-128 characters)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate code challenge using S256 method
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCE{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        "S256",
	}, nil
}
