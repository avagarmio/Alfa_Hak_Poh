package config

import "sync"

// Store — потокобезопасная обёртка над Config для изменения правил в рантайме
// (через API конфигуратора). Хендлер читает правила live, API их обновляет.
type Store struct {
	mu sync.RWMutex
	c  Config
}

// Editable — изменяемое в рантайме подмножество настроек.
type Editable struct {
	AuthEnabled      bool                  `json:"auth_enabled"`
	CompositeMasking bool                  `json:"composite_masking"`
	Systems          map[string]SystemRule `json:"systems"`
}

func NewStore(c *Config) *Store {
	return &Store{c: cloneConfig(c)}
}

func cloneConfig(c *Config) Config {
	out := *c
	out.Systems = cloneSystems(c.Systems)
	return out
}

func cloneSystems(in map[string]SystemRule) map[string]SystemRule {
	out := make(map[string]SystemRule, len(in))
	for k, v := range in {
		v.MaskTypes = append([]string(nil), v.MaskTypes...)
		out[k] = v
	}
	return out
}

// Snapshot возвращает потокобезопасную копию текущей конфигурации.
func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfig(&s.c)
}

func (s *Store) AuthEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c.AuthEnabled
}

func (s *Store) CompositeMasking() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c.CompositeMasking
}

// System возвращает копию правила системы по её ID.
func (s *Store) System(id string) (SystemRule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.c.Systems[id]
	if ok {
		r.MaskTypes = append([]string(nil), r.MaskTypes...)
	}
	return r, ok
}

// Apply заменяет изменяемую часть конфигурации (глобальные флаги и системы).
func (s *Store) Apply(e Editable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c.AuthEnabled = e.AuthEnabled
	s.c.CompositeMasking = e.CompositeMasking
	if e.Systems != nil {
		s.c.Systems = cloneSystems(e.Systems)
	}
}
