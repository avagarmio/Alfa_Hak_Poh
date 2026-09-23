package cache

import (
	"context"
	"sync"
	"time"

	"llm-proxy/internal/types"
)

const (
	numShards   = 64
	shardMask   = numShards - 1
	entryTTL    = 15 * time.Minute
	fnvOffset32 = 2166136261
	fnvPrime32  = 16777619
)

type cacheShard struct {
	sync.RWMutex
	items map[string]types.SessionState
}

type ShardedCache struct {
	shards []*cacheShard
	cancel context.CancelFunc
}

func NewShardedCache() *ShardedCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &ShardedCache{
		shards: make([]*cacheShard, numShards),
		cancel: cancel,
	}

	for i := 0; i < numShards; i++ {
		c.shards[i] = &cacheShard{
			items: make(map[string]types.SessionState, 256),
		}
	}

	go c.startGC(ctx)
	return c
}

func (c *ShardedCache) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *ShardedCache) getShard(key string) *cacheShard {
	var hash uint32 = fnvOffset32
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= fnvPrime32
	}
	return c.shards[hash&shardMask]
}

func (c *ShardedCache) Get(key string) (types.SessionState, bool) {
	shard := c.getShard(key)
	shard.RLock()
	item, exists := shard.items[key]
	shard.RUnlock()

	if !exists || time.Now().After(item.ExpiresAt) {
		return types.SessionState{}, false
	}
	return item, true
}

func (c *ShardedCache) Set(key string, state types.SessionState) {
	shard := c.getShard(key)
	state.ExpiresAt = time.Now().Add(entryTTL)

	shard.Lock()
	shard.items[key] = state
	shard.Unlock()
}

func (c *ShardedCache) startGC(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.cleanup(now)
		}
	}
}

func (c *ShardedCache) cleanup(now time.Time) {
	var expiredKeys []string

	for _, shard := range c.shards {
		expiredKeys = expiredKeys[:0]

		shard.RLock()
		for k, v := range shard.items {
			if now.After(v.ExpiresAt) {
				expiredKeys = append(expiredKeys, k)
			}
		}
		shard.RUnlock()

		if len(expiredKeys) == 0 {
			continue
		}

		shard.Lock()
		for _, k := range expiredKeys {
			if item, exists := shard.items[k]; exists && now.After(item.ExpiresAt) {
				delete(shard.items, k)
			}
		}
		shard.Unlock()
	}
}
