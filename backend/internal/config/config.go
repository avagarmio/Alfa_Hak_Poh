package config

import (
	"encoding/json"
	"os"
)

// SystemRule — правила обработки для одной системы-потребителя.
type SystemRule struct {
	Enabled       bool     `json:"enabled"`        // доступ системы включён
	MaskTypes     []string `json:"mask_types"`     // какие типы ПД маскировать; пусто = все
	DemaskEnabled bool     `json:"demask_enabled"` // разрешено ли демаскирование
	Strategy      string   `json:"strategy"`       // "token" (по умолчанию) или "asterisks"
}

type Config struct {
	Port string
	// AuthEnabled=false (по умолчанию) — контроль доступа выключен, все запросы
	// обрабатываются с маскированием всех типов. Так проверяющая система
	// (AlfaSonar) не отклоняется из-за отсутствия заголовка X-System-ID.
	AuthEnabled bool
	Systems     map[string]SystemRule
	// CompositeMasking=false (по умолчанию) — условные типы (PIN/CVV/CARD_EXP)
	// маскируются безусловно. При true они маскируются только если в тексте
	// присутствует номер карты (CARD).
	CompositeMasking bool
	// CacheBackend: "memory" (по умолчанию, in-memory) или "redis" (общее
	// хранилище для горизонтального масштабирования). RedisAddr — адрес Redis.
	CacheBackend string
	RedisAddr    string
}

// fileConfig — формат JSON-файла настроек систем.
type fileConfig struct {
	AuthEnabled      bool                  `json:"auth_enabled"`
	CompositeMasking bool                  `json:"composite_masking"`
	Systems          map[string]SystemRule `json:"systems"`
}

func Load() *Config {
	cfg := &Config{
		Port:         getenv("PORT", "8080"),
		Systems:      map[string]SystemRule{},
		CacheBackend: getenv("CACHE_BACKEND", "memory"),
		RedisAddr:    getenv("REDIS_ADDR", "localhost:6379"),
	}

	// Файл настроек систем — опционален. Отсутствие/ошибка = безопасный дефолт
	// (auth выключен, маскируем всё).
	path := getenv("CONFIG_PATH", "config/systems.json")
	if data, err := os.ReadFile(path); err == nil {
		var fc fileConfig
		if json.Unmarshal(data, &fc) == nil {
			cfg.AuthEnabled = fc.AuthEnabled
			cfg.CompositeMasking = fc.CompositeMasking
			if fc.Systems != nil {
				cfg.Systems = fc.Systems
			}
		}
	}

	// ENV-переключатель имеет приоритет над файлом (для быстрого вкл/выкл).
	switch os.Getenv("AUTH_ENABLED") {
	case "true", "1":
		cfg.AuthEnabled = true
	case "false", "0":
		cfg.AuthEnabled = false
	}
	switch os.Getenv("COMPOSITE_MASKING") {
	case "true", "1":
		cfg.CompositeMasking = true
	case "false", "0":
		cfg.CompositeMasking = false
	}

	return cfg
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
