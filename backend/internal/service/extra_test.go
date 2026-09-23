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

func TestCompositeMasking(t *testing.T) {
	has := func(detected []string, typ string) bool {
		for _, d := range detected {
			if d == typ {
				return true
			}
		}
		return false
	}

	// composite=off: пин маскируется всегда.
	off := NewService(cache.NewShardedCache())
	if _, d, _ := off.Mask("введите пин-код 1234", nil); !has(d, "PIN") {
		t.Errorf("composite off: PIN должен маскироваться в одиночку, получено %v", d)
	}

	// composite=on: пин без карты — не маскируется; с картой (даже словом) — да.
	on := NewService(cache.NewShardedCache())
	on.SetCompositeMasking(true)
	if _, d, _ := on.Mask("введите пин-код 1234", nil); has(d, "PIN") {
		t.Errorf("composite on: PIN без карты не должен маскироваться, получено %v", d)
	}
	if _, d, _ := on.Mask("карта, пин-код 4321", nil); !has(d, "PIN") {
		t.Errorf("composite on: PIN при наличии карты должен маскироваться, получено %v", d)
	}
	if _, d, _ := on.Mask("оплата 5536913790312149 и пин 4321", nil); !has(d, "PIN") {
		t.Errorf("composite on: PIN при карто-подобном номере должен маскироваться, получено %v", d)
	}
}

func TestCardWithExpiryAndCvv(t *testing.T) {
	s := NewService(cache.NewShardedCache())
	// Карта + срок + CVV одной строкой (без ключевых слов).
	_, detected, _ := s.Mask("2200 1536 9983 8182 12/36 876", nil)
	for _, want := range []string{"CARD", "CARD_EXP", "CVV"} {
		found := false
		for _, d := range detected {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Errorf("ожидался тип %s, получено %v", want, detected)
		}
	}
}

func TestSyntheticStrategy(t *testing.T) {
	s := NewService(cache.NewShardedCache())
	orig := "Клиент Иванов Иван Иванович, тел +7 999 123-45-67, карта 4539 1488 0343 6467 12/26 cvv876"

	masked := s.Process(types.ProcessRequest{Payload: orig, PayloadID: "syn"}, ProcessOptions{DemaskEnabled: true, Strategy: StrategySynthetic})
	if masked == orig {
		t.Fatalf("synthetic не изменил текст")
	}
	if strings.Contains(masked, "Иванов Иван") || strings.Contains(masked, "4539 1488 0343 6467") {
		t.Errorf("synthetic не заменил ПД: %q", masked)
	}
	// Правдоподобно: нет плейсхолдеров-скобок для покрытых типов.
	if strings.Contains(masked, "[FIO_") {
		t.Errorf("synthetic не должен давать [FIO_*]: %q", masked)
	}
	back := s.Process(types.ProcessRequest{Payload: masked, PayloadID: "syn"}, ProcessOptions{DemaskEnabled: true, Strategy: StrategySynthetic})
	if back != orig {
		t.Errorf("synthetic demask != orig:\n  want %q\n  got  %q", orig, back)
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
