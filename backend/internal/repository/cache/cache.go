package cache

import (
	"hash/fnv"
	"sync"
	"time"

	"llm-proxy/internal/types"
)

const (
	numShards = 64
	entryTTL  = 15 * time.Minute
)

type cacheShard struct {
	sync.RWMutex
	items map[string]types.SessionState
}

type ShardedCache struct {
	shards []*cacheShard
}

func NewShardedCache() *ShardedCache {
	c := &ShardedCache{
		shards: make([]*cacheShard, numShards),
	}
	for i := 0; i < numShards; i++ {
		c.shards[i] = &cacheShard{
			items: make(map[string]types.SessionState),
		}
	}

	go c.startGC()
	return c
}

func (c *ShardedCache) getShard(key string) *cacheShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%numShards]
}

func (c *ShardedCache) Get(key string) (types.SessionState, bool) {
	shard := c.getShard(key)
	shard.RLock()
	defer shard.RUnlock()

	item, exists := shard.items[key]
	if !exists || time.Now().After(item.ExpiresAt) {
		return types.SessionState{}, false
	}
	return item, true
}

func (c *ShardedCache) Set(key string, state types.SessionState) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	state.ExpiresAt = time.Now().Add(entryTTL)
	shard.items[key] = state
}

func (c *ShardedCache) startGC() {
	ticker := time.NewTicker(2 * time.Minute)
	for range ticker.C {
		now := time.Now()
		for _, shard := range c.shards {
			shard.Lock()
			for k, v := range shard.items {
				if now.After(v.ExpiresAt) {
					delete(shard.items, k)
				}
			}
			shard.Unlock()
		}
	}
}
