/*
 * JWT Token 黑名单（基于缓存）
 * 功能：登出、密码变更等场景下，将 access token 的 JTI 加入黑名单
 *       在 token 自然过期前阻止其被使用，TTL 自动与 token 剩余生命周期一致
 * 存储：利用 cache.Cache 接口，支持 memory/redis/memcached 等后端
 */
package jwt

import (
	"context"
	"time"

	"server/pkg/cache"
)

/* blacklistKeyPrefix 黑名单 key 前缀 */
const blacklistKeyPrefix = "jwt_blacklist:"

/* Blacklist JWT 黑名单管理器 */
type Blacklist struct {
	cache cache.Cache
}

/*
 * NewBlacklist 创建 JWT 黑名单实例
 * @param c - 缓存实例（nil 表示不启用黑名单）
 */
func NewBlacklist(c cache.Cache) *Blacklist {
	return &Blacklist{cache: c}
}

/*
 * Revoke 将指定 JTI 加入黑名单
 * @param jti       - JWT ID（token 的唯一标识）
 * @param expiresAt - token 的过期时间，用于计算缓存 TTL
 */
func (b *Blacklist) Revoke(jti string, expiresAt time.Time) error {
	if b.cache == nil || jti == "" {
		return nil
	}
	/* TTL = token 剩余生命周期，过期后自动从缓存清除 */
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil /* token 已过期，无需加入黑名单 */
	}
	return b.cache.Set(context.Background(), blacklistKeyPrefix+jti, []byte("1"), ttl)
}

/*
 * IsRevoked 检查指定 JTI 是否已被吊销
 * @param jti - JWT ID
 * @return bool - 已吊销返回 true
 */
func (b *Blacklist) IsRevoked(jti string) bool {
	if b.cache == nil || jti == "" {
		return false
	}
	exists, err := b.cache.Exists(context.Background(), blacklistKeyPrefix+jti)
	if err != nil {
		return false /* 缓存异常时不阻断请求，降级为不检查 */
	}
	return exists
}

/*
 * RevokeAllForUser 吊销用户所有 token（通过 user-level marker）
 * 功能：设置一个 "user:{uid}:revoked_before" 时间戳，
 *       auth 中间件检查 token 的 iat 是否早于该时间戳
 * @param userID    - 用户 ID
 * @param ttl       - marker 存活时间（应与 access token 最大 TTL 一致）
 */
func (b *Blacklist) RevokeAllForUser(userID string, ttl time.Duration) error {
	if b.cache == nil || userID == "" {
		return nil
	}
	key := "jwt_revoke_user:" + userID
	now := []byte(time.Now().UTC().Format(time.RFC3339))
	return b.cache.Set(context.Background(), key, now, ttl)
}

/*
 * IsUserTokenRevoked 检查用户的 token 是否因全局吊销而失效
 * @param userID  - 用户 ID
 * @param issuedAt - token 签发时间
 * @return bool   - 如果 token 签发时间早于吊销时间则返回 true
 */
func (b *Blacklist) IsUserTokenRevoked(userID string, issuedAt time.Time) bool {
	if b.cache == nil || userID == "" {
		return false
	}
	key := "jwt_revoke_user:" + userID
	data, err := b.cache.Get(context.Background(), key)
	if err != nil {
		return false
	}
	revokedBefore, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return false
	}
	return issuedAt.Before(revokedBefore)
}
