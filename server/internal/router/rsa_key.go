/**
 * @file        rsa_key.go
 * @package     router
 * @description ID Token（RS256）签名用 RSA 密钥的持久化加载：存取于 system_configs 表，
 *              保证进程重启后 JWKS 公钥与此前签发的 ID Token 保持稳定，避免密钥漂移导致 RP 验证失败。
 */
package router

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"server/internal/repository"
)

/** system_configs 中持久化 RSA 密钥的键名 */
const (
	configKeyRSAPrivateKeyPEM = "jwt_rsa_private_key_pem"
	configKeyRSAPublicKeyPEM  = "jwt_rsa_public_key_pem"
)

/**
 * loadOrGenerateRSAKey 加载或生成 ID Token 签名用的 RSA 私钥
 *
 * @description
 *   优先从 system_configs 读取持久化私钥（PKCS#1 / PKCS#8 PEM）；
 *   不存在或解析失败时生成 RSA-2048 并写回私钥/公钥 PEM，保证跨重启稳定。
 *
 * @param  {*repository.ConfigRepository} repo - 系统配置仓储
 * @returns {*rsa.PrivateKey, error}
 */
func loadOrGenerateRSAKey(repo *repository.ConfigRepository) (*rsa.PrivateKey, error) {
	if pemStr, err := repo.Get(configKeyRSAPrivateKeyPEM); err == nil && pemStr != "" {
		if key, perr := parseRSAPrivateKeyPEM(pemStr); perr == nil {
			return key, nil
		}
		/* 解析失败（数据损坏/格式不符）：降级为重新生成并覆盖，保证服务可用 */
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := repo.Set(configKeyRSAPrivateKeyPEM, encodeRSAPrivateKeyPEM(key)); err != nil {
		return nil, err
	}
	if pubPEM, perr := encodeRSAPublicKeyPEM(&key.PublicKey); perr == nil {
		_ = repo.Set(configKeyRSAPublicKeyPEM, pubPEM)
	}
	return key, nil
}

/**
 * parseRSAPrivateKeyPEM 解析 PEM 编码的 RSA 私钥（兼容 PKCS#1 与 PKCS#8）
 *
 * @param  {string} s - PEM 文本
 * @returns {*rsa.PrivateKey, error}
 */
func parseRSAPrivateKeyPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM is not an RSA private key")
	}
	return rsaKey, nil
}

/**
 * encodeRSAPrivateKeyPEM 将 RSA 私钥编码为 PKCS#1 PEM
 *
 * @param  {*rsa.PrivateKey} key
 * @returns {string} PEM 文本
 */
func encodeRSAPrivateKeyPEM(key *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

/**
 * encodeRSAPublicKeyPEM 将 RSA 公钥编码为 PKIX PEM
 *
 * @param  {*rsa.PublicKey} pub
 * @returns {string, error} PEM 文本
 */
func encodeRSAPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
