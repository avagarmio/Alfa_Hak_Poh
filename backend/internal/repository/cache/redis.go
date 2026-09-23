package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"llm-proxy/internal/types"
)

// RedisStore — общее хранилище пар для нескольких инстансов сервиса
// (горизонтальное масштабирование). Реализует тот же контракт Get/Set, что и
// ShardedCache. TTL и вытеснение выполняет сам Redis.
type RedisStore struct {
	client *redis.Client
	ttl    time.Duration
	ctx    context.Context
}

// NewRedisStore подключается к Redis и проверяет доступность (PING).
func NewRedisStore(addr string) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx := context.Background()
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &RedisStore{client: client, ttl: entryTTL, ctx: ctx}, nil
}

func (r *RedisStore) Get(key string) (types.SessionState, bool) {
	data, err := r.client.Get(r.ctx, key).Bytes()
	if err != nil {
		return types.SessionState{}, false
	}
	var st types.SessionState
	if json.Unmarshal(data, &st) != nil {
		return types.SessionState{}, false
	}
	return st, true
}

func (r *RedisStore) Set(key string, state types.SessionState) {
	state.ExpiresAt = time.Now().Add(r.ttl)
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	r.client.Set(r.ctx, key, data, r.ttl)
}

func (r *RedisStore) Stop() { _ = r.client.Close() }
