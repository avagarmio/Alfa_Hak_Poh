package service

import (
	"strings"
	"testing"

	"llm-proxy/internal/repository/cache"
	"llm-proxy/internal/types"
)

func newSvc() *Service {
	return NewService(cache.NewShardedCache())
}

func typeSet(types []string) map[string]bool {
	m := make(map[string]bool, len(types))
	for _, t := range types {
		m[t] = true
	}
	return m
}

// --- Детекция типов ПД ---

func TestMaskDetectsTypes(t *testing.T) {
	s := newSvc()
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"email+phone", "почта a.b@mail.ru тел +7 999 123-45-67", []string{"EMAIL", "PHONE"}},
		{"passport_joined", "паспорт 4509 123456", []string{"PASSPORT"}},
		{"passport_separated", "серия 4509 номер 123456", []string{"PASSPORT"}},
		{"fio", "Иванов Иван Иванович пришёл", []string{"FIO"}},
		{"address", "г. Москва, ул. Тверская, д. 12, кв. 5", []string{"ADDRESS"}},
		{"inn", "ИНН 7707083893 указан", []string{"INN"}},
		{"date_text", "родился 12 мая 1995 года", []string{"DATE"}},
		{"citizenship", "гражданин РФ", []string{"CITIZENSHIP"}},
		{"card_holder", "держатель IVAN PETROV", []string{"CARD_HOLDER"}},
		// Морфологическая детекция ФИО: строчные, без маркера, склонения, отчество.
		{"fio_lowercase", "клиент иванов иван оплатил", []string{"FIO"}},
		{"fio_no_marker", "меня зовут пётр воробьёв", []string{"FIO"}},
		{"fio_inflected", "перевод для сергея петрова", []string{"FIO"}},
		{"fio_patronymic_bridge", "гагарян ашот арутюнович", []string{"FIO"}},
		// Вариации телефона и ПИН (регрессии по багам из UI).
		{"phone_no_plus", "номер телефона 7 999 123-45-67", []string{"PHONE"}},
		{"phone_parens", "тел +7 (999) 999-99-99", []string{"PHONE"}},
		{"phone_double_dash", "звоните 8 (999) 123--45-67", []string{"PHONE"}},
		{"phone_solid", "89991234567", []string{"PHONE"}},
		{"pin_with_word", "пин-код карты 4321", []string{"PIN"}},
		{"driver_declined", "серия и номер водительского удостоверения 77 АА 123456", []string{"DRIVER"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, detected := s.Mask(c.input, nil)
			got := typeSet(detected)
			for _, w := range c.want {
				if !got[w] {
					t.Errorf("Mask(%q): ожидался тип %s, получено %v", c.input, w, detected)
				}
			}
		})
	}
}

// --- Отсутствие ложных срабатываний ---

func TestMaskFalsePositives(t *testing.T) {
	s := newSvc()
	// Публичная личность и топоним/юрлицо не должны маскироваться.
	cases := []string{
		"Поэт Александр Пушкин",
		"Заседание в Москва Сити",
		"Компания ООО Ромашка",
		// Слова с «фамильными» окончаниями, но не ПД (морфология не должна ловить).
		"оплатил бензин на заправке",
		"купил молоко и картину",
		"директор уехал в магазин",
	}
	for _, in := range cases {
		out, _ := s.Mask(in, nil)
		// Хотя бы одно ключевое слово должно остаться нетронутым (без '*').
		key := strings.Fields(in)[len(strings.Fields(in))-1]
		if !strings.Contains(out, key) {
			t.Errorf("ложное срабатывание: %q -> %q (слово %q замаскировано)", in, out, key)
		}
	}
}

func TestMaskEmptyAndNoPD(t *testing.T) {
	s := newSvc()
	for _, in := range []string{"", "обычный текст без пд", "просто предложение."} {
		out, detected := s.Mask(in, nil)
		if out != in {
			t.Errorf("Mask(%q) изменил строку без ПД: %q", in, out)
		}
		if detected != nil {
			t.Errorf("Mask(%q): ожидался nil-список типов, получено %v", in, detected)
		}
	}
}

// --- Фильтрация типов по системе ---

func TestMaskAllowedTypesFilter(t *testing.T) {
	s := newSvc()
	in := "Иванов Иван, тел +7 999 123-45-67, почта a@b.ru"
	// Разрешаем только телефон.
	out, detected := s.Mask(in, map[string]struct{}{"PHONE": {}})
	got := typeSet(detected)
	if !got["PHONE"] {
		t.Errorf("PHONE должен быть найден, получено %v", detected)
	}
	if got["FIO"] || got["EMAIL"] {
		t.Errorf("при фильтре PHONE не должно быть FIO/EMAIL, получено %v", detected)
	}
	// Почта и имя остаются в открытом виде.
	if !strings.Contains(out, "a@b.ru") {
		t.Errorf("email не должен маскироваться при фильтре PHONE: %q", out)
	}
	if !strings.Contains(out, "Иванов") {
		t.Errorf("ФИО не должно маскироваться при фильтре PHONE: %q", out)
	}
}

// --- Round-trip и идемпотентность через Process ---

func TestProcessRoundTrip(t *testing.T) {
	s := newSvc()
	orig := "Клиент Иванов Иван, паспорт 4509 123456, карта 4539 1488 0343 6467"

	masked := s.Process(types.ProcessRequest{Payload: orig, PayloadID: "id-1"}, DefaultOptions())
	if masked == orig {
		t.Fatalf("прямой шаг не замаскировал строку")
	}

	retry := s.Process(types.ProcessRequest{Payload: orig, PayloadID: "id-1"}, DefaultOptions())
	if retry != masked {
		t.Errorf("идемпотентность нарушена: %q != %q", retry, masked)
	}

	back := s.Process(types.ProcessRequest{Payload: masked, PayloadID: "id-1"}, DefaultOptions())
	if back != orig {
		t.Errorf("демаскирование не восстановило оригинал:\n  want %q\n  got  %q", orig, back)
	}
}

func TestProcessDemaskDisabled(t *testing.T) {
	s := newSvc()
	orig := "Иванов Иван, тел +7 999 123-45-67"
	opts := ProcessOptions{MaskTypes: nil, DemaskEnabled: false}

	masked := s.Process(types.ProcessRequest{Payload: orig, PayloadID: "id-2"}, opts)
	back := s.Process(types.ProcessRequest{Payload: masked, PayloadID: "id-2"}, opts)

	if back == orig {
		t.Errorf("при выключенном демаске оригинал не должен раскрываться: %q", back)
	}
	if back != masked {
		t.Errorf("обратный шаг должен вернуть присланную строку: want %q got %q", masked, back)
	}
}

func TestProcessCyrillicIntegrity(t *testing.T) {
	s := newSvc()
	orig := "Ф.И.О.: Пётр Воробьёв, адрес: г. Москва, ул. Ёлочная, д. 3"
	masked := s.Process(types.ProcessRequest{Payload: orig, PayloadID: "cyr"}, DefaultOptions())
	back := s.Process(types.ProcessRequest{Payload: masked, PayloadID: "cyr"}, DefaultOptions())
	if back != orig {
		t.Errorf("кириллица не восстановлена побайтно:\n  want %q\n  got  %q", orig, back)
	}
}

// --- Луна ---

func TestIsValidLuhn(t *testing.T) {
	valid := []string{"4539 1488 0343 6467", "4111111111111111", "5555555555554444"}
	invalid := []string{"4276 3800 1234 5678", "1234567890123", "0000"}
	for _, v := range valid {
		if !isValidLuhn(v) {
			t.Errorf("isValidLuhn(%q) = false, ожидалось true", v)
		}
	}
	for _, v := range invalid {
		if isValidLuhn(v) {
			t.Errorf("isValidLuhn(%q) = true, ожидалось false", v)
		}
	}
}

func TestCardOnlyValidLuhnMasked(t *testing.T) {
	s := newSvc()
	// Невалидный по Луну номер не маскируется.
	out, detected := s.Mask("оплата 4276 3800 1234 5678", nil)
	if typeSet(detected)["CARD"] {
		t.Errorf("невалидная карта не должна детектироваться: %v", detected)
	}
	if !strings.Contains(out, "4276 3800 1234 5678") {
		t.Errorf("невалидная карта не должна маскироваться: %q", out)
	}
}

// --- mergeSpans ---

func TestMergeSpans(t *testing.T) {
	cases := []struct {
		name string
		in   []types.Span
		want []types.Span
	}{
		{
			"overlap",
			[]types.Span{{Start: 0, End: 5}, {Start: 3, End: 8}},
			[]types.Span{{Start: 0, End: 8}},
		},
		{
			"adjacent_touching",
			[]types.Span{{Start: 0, End: 5}, {Start: 5, End: 10}},
			[]types.Span{{Start: 0, End: 10}},
		},
		{
			"nested",
			[]types.Span{{Start: 0, End: 10}, {Start: 3, End: 6}},
			[]types.Span{{Start: 0, End: 10}},
		},
		{
			"disjoint",
			[]types.Span{{Start: 0, End: 3}, {Start: 5, End: 8}},
			[]types.Span{{Start: 0, End: 3}, {Start: 5, End: 8}},
		},
		{
			"unsorted",
			[]types.Span{{Start: 5, End: 8}, {Start: 0, End: 3}},
			[]types.Span{{Start: 0, End: 3}, {Start: 5, End: 8}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeSpans(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("mergeSpans(%v) = %v, ожидалось %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i].Start != c.want[i].Start || got[i].End != c.want[i].End {
					t.Errorf("mergeSpans[%d] = {%d,%d}, ожидалось {%d,%d}",
						i, got[i].Start, got[i].End, c.want[i].Start, c.want[i].End)
				}
			}
		})
	}
}

// --- Бенчмарк на большом тексте (ориентир ТЗ: до 100 000 токенов) ---

func BenchmarkMaskLarge(b *testing.B) {
	s := newSvc()
	para := "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 999 123-45-67, " +
		"почта ivanov@mail.ru, карта 4539 1488 0343 6467, г. Москва, ул. Тверская, д. 12. "
	// ~400k символов ≈ 100k токенов
	input := strings.Repeat(para, 2800)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Mask(input, nil)
	}
}
