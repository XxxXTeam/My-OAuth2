package cache

import (
	"context"
	"testing"
	"time"
)

func newTestMemoryCache() *MemoryCache {
	return NewMemoryCache(5 * time.Minute)
}

/* ========== Set & Get ========== */

func TestMemoryCache_Set_And_Get(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "key1", []byte("value1"), 0); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	got, err := mc.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if string(got) != "value1" {
		t.Errorf("Get() = %q, want %q", string(got), "value1")
	}
}

func TestMemoryCache_Get_NotFound(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()

	_, err := mc.Get(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Get(nonexistent) = %v, want ErrNotFound", err)
	}
}

func TestMemoryCache_Get_ReturnsCopy(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	mc.Set(ctx, "k", []byte("original"), 0)
	got, _ := mc.Get(ctx, "k")
	got[0] = 'X' /* 修改返回值不应影响缓存 */

	got2, _ := mc.Get(ctx, "k")
	if string(got2) != "original" {
		t.Errorf("Get() should return a copy, but cache was mutated to %q", string(got2))
	}
}

/* ========== TTL 过期 ========== */

func TestMemoryCache_TTL_Expired(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	mc.Set(ctx, "ephemeral", []byte("gone soon"), 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)

	_, err := mc.Get(ctx, "ephemeral")
	if err != ErrNotFound {
		t.Errorf("Get(expired) = %v, want ErrNotFound", err)
	}
}

func TestMemoryCache_DefaultTTL(t *testing.T) {
	mc := NewMemoryCache(100 * time.Millisecond)
	defer mc.Close()
	ctx := context.Background()

	mc.Set(ctx, "default-ttl", []byte("v"), 0) /* ttl=0 使用默认值 */
	time.Sleep(150 * time.Millisecond)

	_, err := mc.Get(ctx, "default-ttl")
	if err != ErrNotFound {
		t.Errorf("Get(default-ttl expired) = %v, want ErrNotFound", err)
	}
}

/* ========== Delete ========== */

func TestMemoryCache_Delete(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	mc.Set(ctx, "del-me", []byte("v"), 0)
	mc.Delete(ctx, "del-me")

	_, err := mc.Get(ctx, "del-me")
	if err != ErrNotFound {
		t.Errorf("Get(deleted) = %v, want ErrNotFound", err)
	}
}

func TestMemoryCache_Delete_NonExistent(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	/* 删除不存在的 key 不应报错 */
	if err := mc.Delete(context.Background(), "nope"); err != nil {
		t.Errorf("Delete(nonexistent) error: %v", err)
	}
}

/* ========== Exists ========== */

func TestMemoryCache_Exists(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	mc.Set(ctx, "exists-key", []byte("v"), 0)

	ok, err := mc.Exists(ctx, "exists-key")
	if err != nil || !ok {
		t.Errorf("Exists(existing) = %v, %v, want true, nil", ok, err)
	}

	ok2, _ := mc.Exists(ctx, "no-key")
	if ok2 {
		t.Error("Exists(nonexistent) should return false")
	}
}

func TestMemoryCache_Exists_Expired(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	mc.Set(ctx, "exp", []byte("v"), 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)

	ok, _ := mc.Exists(ctx, "exp")
	if ok {
		t.Error("Exists(expired) should return false")
	}
}

/* ========== Ping & Close ========== */

func TestMemoryCache_Ping(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	if err := mc.Ping(context.Background()); err != nil {
		t.Errorf("Ping() error: %v", err)
	}
}

func TestMemoryCache_Close_Idempotent(t *testing.T) {
	mc := newTestMemoryCache()
	if err := mc.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}
	/* 二次 Close 不应 panic（已用 sync.Once 保护） */
	if err := mc.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
}

/* ========== 泛型辅助函数 ========== */

func TestGetJSON_SetJSON(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()
	ctx := context.Background()

	type payload struct {
		Name  string `json:"name"`
		Score int    `json:"score"`
	}

	input := payload{Name: "test", Score: 42}
	if err := SetJSON(ctx, mc, "json-key", input, 0); err != nil {
		t.Fatalf("SetJSON() error: %v", err)
	}

	got, err := GetJSON[payload](ctx, mc, "json-key")
	if err != nil {
		t.Fatalf("GetJSON() error: %v", err)
	}
	if got.Name != "test" || got.Score != 42 {
		t.Errorf("GetJSON() = %+v, want {Name:test Score:42}", got)
	}
}

func TestGetJSON_NotFound(t *testing.T) {
	mc := newTestMemoryCache()
	defer mc.Close()

	_, err := GetJSON[string](context.Background(), mc, "missing")
	if err == nil {
		t.Error("GetJSON(missing) should return error")
	}
}
