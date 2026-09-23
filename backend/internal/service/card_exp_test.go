package service

import (
	"strings"
	"testing"
	"time"

	"llm-proxy/internal/repository/cache"
)

func TestIsFutureExpiry(t *testing.T) {
	now := time.Date(2026, time.September, 15, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		mm, yy int
		want   bool
	}{
		{9, 26, true},   // текущий месяц
		{12, 26, true},  // позже в этом году
		{1, 27, true},   // следующий год
		{8, 26, false},  // прошлый месяц этого года
		{12, 25, false}, // прошлый год
		{0, 30, false},  // невалидный месяц
		{13, 30, false}, // невалидный месяц
		{6, 2030, true}, // четырёхзначный год
	}
	for _, c := range cases {
		if got := isFutureExpiry(c.mm, c.yy, now); got != c.want {
			t.Errorf("isFutureExpiry(%d,%d) = %v, ожидалось %v", c.mm, c.yy, got, c.want)
		}
	}
}

func TestCardExpiryDetection(t *testing.T) {
	s := NewService(cache.NewShardedCache())

	// Должны маскироваться (дата в будущем: 12/40, 09/40).
	mask := []string{
		"карта 4276 3800 1234 5678, срок 12/40",
		"действительна до 09.40",
		"годна 03-41",
	}
	for _, in := range mask {
		out, _, m := s.Mask(in, nil)
		if !strings.Contains(out, "[CARD_EXP_1]") || len(m) == 0 {
			t.Errorf("срок карты не задетектирован: %q -> %q", in, out)
		}
	}

	// НЕ должны (нет карточного контекста / просрочено / одиночная цифра месяца).
	keep := []string{
		"цена товара 10.99 рублей",
		"версия 12.30 сборки",
		"счёт 5/2041 оплачен",
	}
	for _, in := range keep {
		out, _, _ := s.Mask(in, nil)
		if strings.Contains(out, "CARD_EXP") {
			t.Errorf("ложное срабатывание срока карты: %q -> %q", in, out)
		}
	}
}
