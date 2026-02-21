package repository

import (
	"context"
	"time"

	"server/internal/model"
	"server/pkg/cache"

	"github.com/google/uuid"
)

/* 联邦提供者缓存配置 */
const (
	providerCacheKey = "providers:enabled"
	providerCacheTTL = 2 * time.Minute
)

/*
 * CachedFederationRepository 带缓存的联邦提供者仓储
 * 功能：在 FederationRepository 基础上增加缓存层，减少 ListProviders 热路径的 DB 查询
 *       支持 memory / redis 后端
 */
type CachedFederationRepository struct {
	*FederationRepository
	cache cache.Cache
}

/*
 * NewCachedFederationRepository 创建带缓存的联邦仓储实例
 * @param repo - 基础联邦仓储
 * @param c    - 缓存实例（支持 memory / redis）
 */
func NewCachedFederationRepository(repo *FederationRepository, c cache.Cache) *CachedFederationRepository {
	return &CachedFederationRepository{
		FederationRepository: repo,
		cache:                c,
	}
}

/*
 * FindAllEnabled 获取已启用的联邦提供者（优先缓存，未命中时回源 DB）
 * @return []model.FederatedProvider - 提供者列表
 */
func (r *CachedFederationRepository) FindAllEnabled() ([]model.FederatedProvider, error) {
	ctx := context.Background()

	// Try cache first
	providers, err := cache.GetJSON[[]model.FederatedProvider](ctx, r.cache, providerCacheKey)
	if err == nil {
		return providers, nil
	}

	// Cache miss — query DB
	providers, err = r.FederationRepository.FindAllEnabled()
	if err != nil {
		return nil, err
	}

	// Store in cache (fire-and-forget)
	_ = cache.SetJSON(ctx, r.cache, providerCacheKey, providers, providerCacheTTL)

	return providers, nil
}

/* invalidateCache 清除提供者缓存（写操作后调用） */
func (r *CachedFederationRepository) invalidateCache() {
	_ = r.cache.Delete(context.Background(), providerCacheKey)
}

/* CreateProvider 创建提供者并失效缓存 */
func (r *CachedFederationRepository) CreateProvider(provider *model.FederatedProvider) error {
	err := r.FederationRepository.CreateProvider(provider)
	if err == nil {
		r.invalidateCache()
	}
	return err
}

/* UpdateProvider 更新提供者并失效缓存 */
func (r *CachedFederationRepository) UpdateProvider(provider *model.FederatedProvider) error {
	err := r.FederationRepository.UpdateProvider(provider)
	if err == nil {
		r.invalidateCache()
	}
	return err
}

/* DeleteProvider 删除提供者并失效缓存 */
func (r *CachedFederationRepository) DeleteProvider(id uuid.UUID) error {
	err := r.FederationRepository.DeleteProvider(id)
	r.invalidateCache()
	return err
}
