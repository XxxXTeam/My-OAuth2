/**
 * @file        rsa_key_test.go
 * @package     router
 * @description loadOrGenerateRSAKey 的持久化稳定性测试：验证密钥写入 system_configs 后跨调用（模拟重启）保持一致，
 *              并可通过 SetRSAKey 注入 Manager 完成 ID Token 的 RS256 往返签发/验证。
 */
package router

import (
	"testing"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

/** setupConfigTestDB 建立仅含 system_configs 表的内存数据库 */
func setupConfigTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.SystemConfig{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

/**
 * TestLoadOrGenerateRSAKey_PersistsAndReloadsStableKey
 * 首次调用生成并持久化 RSA 私钥；二次调用（模拟进程重启）必须返回同一密钥，
 * 且 system_configs 中同时写入了私钥与公钥 PEM。
 */
func TestLoadOrGenerateRSAKey_PersistsAndReloadsStableKey(t *testing.T) {
	repo := repository.NewConfigRepository(setupConfigTestDB(t))

	first, err := loadOrGenerateRSAKey(repo)
	if err != nil {
		t.Fatalf("first loadOrGenerateRSAKey: %v", err)
	}

	privPEM, err := repo.Get(configKeyRSAPrivateKeyPEM)
	if err != nil || privPEM == "" {
		t.Fatalf("private key PEM not persisted: err=%v empty=%v", err, privPEM == "")
	}
	if pubPEM, perr := repo.Get(configKeyRSAPublicKeyPEM); perr != nil || pubPEM == "" {
		t.Fatalf("public key PEM not persisted: err=%v empty=%v", perr, pubPEM == "")
	}

	second, err := loadOrGenerateRSAKey(repo)
	if err != nil {
		t.Fatalf("second loadOrGenerateRSAKey: %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("reloaded RSA key differs from persisted key (key drift on restart)")
	}
}

/**
 * TestLoadOrGenerateRSAKey_InjectedKeyValidatesIDToken
 * 持久化密钥注入 Manager 后，签发的 RS256 ID Token 可被同一（重载）密钥验证通过。
 */
func TestLoadOrGenerateRSAKey_InjectedKeyValidatesIDToken(t *testing.T) {
	repo := repository.NewConfigRepository(setupConfigTestDB(t))

	key, err := loadOrGenerateRSAKey(repo)
	if err != nil {
		t.Fatalf("loadOrGenerateRSAKey: %v", err)
	}

	issuer := "https://oauth.example.test"
	signer := jwt.NewManager("test-secret-with-enough-length", issuer)
	signer.SetRSAKey(key)

	idToken, err := signer.GenerateClientIDTokenWithIssuerAndNonceAndAuthTime(
		uuid.New(), "a@b.com", "user", "user", "client-1", "client-secret", issuer, "openid profile", "", time.Now().Unix(), 5*time.Minute,
	)
	if err != nil {
		t.Fatalf("GenerateClientIDToken: %v", err)
	}

	/* 模拟重启：新 Manager 从持久化仓储重载同一密钥后应能验证此前签发的 ID Token */
	reloaded, err := loadOrGenerateRSAKey(repo)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	verifier := jwt.NewManager("test-secret-with-enough-length", issuer)
	verifier.SetRSAKey(reloaded)

	claims, err := verifier.ValidateClientIDTokenWithIssuer(idToken, "client-1", "client-secret", issuer)
	if err != nil {
		t.Fatalf("ValidateClientIDTokenWithIssuer after reload: %v", err)
	}
	if claims.ClientID != "client-1" || claims.TokenType != jwt.TokenTypeIDToken {
		t.Fatalf("unexpected claims: clientID=%q type=%q", claims.ClientID, claims.TokenType)
	}
}
