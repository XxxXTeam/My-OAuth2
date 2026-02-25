package jwt

import (
	"testing"
	"time"

	"server/pkg/cache"
)

func newTestCache() cache.Cache {
	return cache.NewMemoryCache(5 * time.Minute)
}

/* ========== Revoke & IsRevoked ========== */

func TestBlacklist_Revoke_And_IsRevoked(t *testing.T) {
	bl := NewBlacklist(newTestCache())

	jti := "test-jti-001"
	expiresAt := time.Now().Add(5 * time.Minute)

	if err := bl.Revoke(jti, expiresAt); err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}
	if !bl.IsRevoked(jti) {
		t.Error("IsRevoked() should return true after Revoke()")
	}
}

func TestBlacklist_IsRevoked_NotRevoked(t *testing.T) {
	bl := NewBlacklist(newTestCache())
	if bl.IsRevoked("non-existent-jti") {
		t.Error("IsRevoked() should return false for non-revoked JTI")
	}
}

func TestBlacklist_Revoke_ExpiredToken_NoOp(t *testing.T) {
	bl := NewBlacklist(newTestCache())
	/* 已过期的 token 不应加入黑名单 */
	err := bl.Revoke("expired-jti", time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("Revoke(expired) error: %v", err)
	}
	if bl.IsRevoked("expired-jti") {
		t.Error("expired token should not be in blacklist")
	}
}

func TestBlacklist_NilCache_NoError(t *testing.T) {
	bl := NewBlacklist(nil)
	/* nil cache 不应 panic 或报错 */
	if err := bl.Revoke("jti", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("Revoke(nil cache) error: %v", err)
	}
	if bl.IsRevoked("jti") {
		t.Error("nil cache should always return false")
	}
}

func TestBlacklist_EmptyJTI_NoOp(t *testing.T) {
	bl := NewBlacklist(newTestCache())
	if err := bl.Revoke("", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("Revoke(empty jti) error: %v", err)
	}
	if bl.IsRevoked("") {
		t.Error("empty JTI should return false")
	}
}

/* ========== RevokeAllForUser & IsUserTokenRevoked ========== */

func TestBlacklist_RevokeAllForUser(t *testing.T) {
	bl := NewBlacklist(newTestCache())
	userID := "user-123"

	if err := bl.RevokeAllForUser(userID, 10*time.Minute); err != nil {
		t.Fatalf("RevokeAllForUser() error: %v", err)
	}

	/* 吊销时间之前签发的 token 应被认为已吊销 */
	oldIssuedAt := time.Now().Add(-1 * time.Minute)
	if !bl.IsUserTokenRevoked(userID, oldIssuedAt) {
		t.Error("token issued before revocation should be revoked")
	}

	/* 吊销时间之后签发的 token 应被认为有效 */
	newIssuedAt := time.Now().Add(1 * time.Second)
	time.Sleep(10 * time.Millisecond) /* 确保时间差 */
	if bl.IsUserTokenRevoked(userID, newIssuedAt) {
		t.Error("token issued after revocation should NOT be revoked")
	}
}

func TestBlacklist_IsUserTokenRevoked_NoRevocation(t *testing.T) {
	bl := NewBlacklist(newTestCache())
	/* 未吊销用户的 token 应该有效 */
	if bl.IsUserTokenRevoked("user-no-revoke", time.Now()) {
		t.Error("user without revocation should return false")
	}
}

func TestBlacklist_RevokeAllForUser_NilCache(t *testing.T) {
	bl := NewBlacklist(nil)
	if err := bl.RevokeAllForUser("user-123", 10*time.Minute); err != nil {
		t.Fatalf("RevokeAllForUser(nil cache) error: %v", err)
	}
	if bl.IsUserTokenRevoked("user-123", time.Now()) {
		t.Error("nil cache should return false")
	}
}
