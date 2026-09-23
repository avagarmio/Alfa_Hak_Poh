package service

import (
	"strings"
	"testing"

	"llm-proxy/internal/repository/cache"
	"llm-proxy/internal/types"
)

func TestExtraDocsDetection(t *testing.T) {
	s := NewService(cache.NewShardedCache())
	cases := []struct {
		in   string
		want string
	}{
		{"Загран: серия 71 № 9876543", "PASSPORT_INTL"},
		{"загранпаспорт 71 9876543", "PASSPORT_INTL"},
		{"СНИЛС 112-233-445 95", "SNILS"},
		{"снилс 11223344595", "SNILS"},
		{"112-233-445 95", "SNILS"}, // голый формат
	}
	for _, c := range cases {
		_, detected, _ := s.Mask(c.in, nil)
		found := false
		for _, d := range detected {
			if d == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: ожидался тип %s, получено %v", c.in, c.want, detected)
		}
	}
}

func TestStrategySelection(t *testing.T) {
	orig := "Клиент Иванов Иван, тел +7 999 123-45-67"

	// Токены: результат содержит плейсхолдеры, демаск восстанавливает оригинал.
	st := NewService(cache.NewShardedCache())
	tok := st.Process(types.ProcessRequest{Payload: orig, PayloadID: "t"}, ProcessOptions{DemaskEnabled: true, Strategy: StrategyToken})
	if !strings.Contains(tok, "[") {
		t.Errorf("token-стратегия не дала плейсхолдеров: %q", tok)
	}
	if back := st.Process(types.ProcessRequest{Payload: tok, PayloadID: "t"}, ProcessOptions{DemaskEnabled: true, Strategy: StrategyToken}); back != orig {
		t.Errorf("token demask != orig: %q", back)
	}

	// Звёздочки: результат содержит '*', демаск восстанавливает из кэша.
	sa := NewService(cache.NewShardedCache())
	ast := sa.Process(types.ProcessRequest{Payload: orig, PayloadID: "a"}, ProcessOptions{DemaskEnabled: true, Strategy: StrategyAsterisks})
	if !strings.Contains(ast, "*") {
		t.Errorf("asterisks-стратегия не дала звёздочек: %q", ast)
	}
	if back := sa.Process(types.ProcessRequest{Payload: ast, PayloadID: "a"}, ProcessOptions{DemaskEnabled: true, Strategy: StrategyAsterisks}); back != orig {
		t.Errorf("asterisks demask != orig: %q", back)
	}
}
