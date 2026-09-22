package service

import (
	"regexp"
	"sort"
	"strconv"
	"unicode"

	"llm-proxy/internal/repository/cache"
	"llm-proxy/internal/types"
)

type Service struct {
	cache      *cache.ShardedCache
	reEmail    *regexp.Regexp
	rePhone    *regexp.Regexp
	rePassport *regexp.Regexp
	rePassCode *regexp.Regexp
	reCard     *regexp.Regexp
	reCVV      *regexp.Regexp
	rePIN      *regexp.Regexp
	reDate     *regexp.Regexp
	reDriver   *regexp.Regexp
	reINN      *regexp.Regexp
	reFIO      *regexp.Regexp
}

func NewService(c *cache.ShardedCache) *Service {
	return &Service{
		cache:      c,
		reEmail:    regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		rePhone:    regexp.MustCompile(`(?:\+7|8)[\s\-]?(?:\(?\d{3}\)?[\s\-]?)\d{3}[\s\-]?\d{2}[\s\-]?\d{2}`),
		rePassport: regexp.MustCompile(`(?i)(?:паспорт\s*(?:рф)?[^\d]*?)?(\b\d{2}\s*\d{2}\s*\d{6}\b)`),
		rePassCode: regexp.MustCompile(`\b\d{3}-\d{3}\b`),
		reCard:     regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
		reCVV:      regexp.MustCompile(`(?i)(?:cvv|cvc|код)[^\d]{1,5}(\b\d{3}\b)`),
		rePIN:      regexp.MustCompile(`(?i)(?:пин|pin|пин-код)[^\d]{1,5}(\b\d{4}\b)`),
		reDate:     regexp.MustCompile(`\b(?:\d{2}[./-]\d{2}[./-]\d{4}|\d{4}[./-]\d{2}[./-]\d{2})\b`),
		reDriver:   regexp.MustCompile(`(?i)(?:водительское|в/у|удостоверение)[^\d]*?(\b\d{2}\s*(?:\d{2}|[А-ЯA-Z]{2})\s*\d{6}\b)`),
		reINN:      regexp.MustCompile(`(?i)(?:инн)[^\d]{1,5}(\b\d{10}\b|\b\d{12}\b)`),
		reFIO:      regexp.MustCompile(`\b([А-ЯЁ][а-яё]+)\s+([А-ЯЁ][а-яё]+)(?:\s+([А-ЯЁ][а-яё]+))?\b`),
	}
}

// Process координирует шаги маскирования, демаскирования и ретраев
func (s *Service) Process(req types.ProcessRequest) string {
	state, exists := s.cache.Get(req.PayloadID)

	if !exists {
		// Прямой шаг: новое значение payload_id -> маскируем и кэшируем
		masked := s.Mask(req.Payload)
		s.cache.Set(req.PayloadID, types.SessionState{
			OriginalText: req.Payload,
			MaskedText:   masked,
		})
		return masked
	}

	// Идемпотентный ретрай маскирования
	if req.Payload == state.OriginalText {
		return state.MaskedText
	}

	// Обратный шаг (демаскирование): пришел ранее замаскированный текст
	return state.OriginalText
}

// Mask находит и маскирует ПД с сохранением разделителей и длины
func (s *Service) Mask(input string) string {
	runes := []rune(input)
	var spans []types.Span

	spans = append(spans, s.findSpans(input, runes, s.reEmail, 0, "EMAIL")...)
	spans = append(spans, s.findSpans(input, runes, s.rePhone, 0, "PHONE")...)
	spans = append(spans, s.findSpans(input, runes, s.rePassport, 1, "PASSPORT")...)
	spans = append(spans, s.findSpans(input, runes, s.rePassCode, 0, "PASS_CODE")...)
	spans = append(spans, s.findSpans(input, runes, s.reDate, 0, "DATE")...)
	spans = append(spans, s.findSpans(input, runes, s.reDriver, 1, "DRIVER")...)
	spans = append(spans, s.findSpans(input, runes, s.reINN, 1, "INN")...)
	spans = append(spans, s.findSpans(input, runes, s.reCVV, 1, "CVV")...)
	spans = append(spans, s.findSpans(input, runes, s.rePIN, 1, "PIN")...)

	// Карты с обязательной проверкой контрольной суммы Луна
	cardMatches := s.reCard.FindAllStringIndex(input, -1)
	for _, match := range cardMatches {
		candidate := input[match[0]:match[1]]
		if isValidLuhn(candidate) {
			rStart := len([]rune(input[:match[0]]))
			rEnd := rStart + len([]rune(candidate))
			spans = append(spans, types.Span{Start: rStart, End: rEnd, Type: "CARD"})
		}
	}

	// ФИО (с защитой от точек в конце предложений)
	fioMatches := s.reFIO.FindAllStringSubmatchIndex(input, -1)
	for _, match := range fioMatches {
		if match[0] > 0 && input[match[0]-1] == '.' {
			continue
		}
		rStart := len([]rune(input[:match[0]]))
		rEnd := len([]rune(input[:match[1]]))
		spans = append(spans, types.Span{Start: rStart, End: rEnd, Type: "FIO"})
	}

	if len(spans) == 0 {
		return input
	}

	spans = mergeSpans(spans)

	out := make([]rune, len(runes))
	copy(out, runes)

	for _, span := range spans {
		length := span.End - span.Start
		for i := span.Start; i < span.End; i++ {
			// Сохраняем форматирующие знаки
			if unicode.IsSpace(out[i]) || out[i] == '-' || out[i] == '.' || out[i] == '@' || out[i] == '+' {
				continue
			}

			// Для длинных сущностей оставляем края (Банковский стандарт)
			if length > 4 {
				if i == span.Start || i == span.End-1 {
					continue
				}
			}
			out[i] = '*'
		}
	}

	return string(out)
}

func (s *Service) findSpans(input string, _ []rune, re *regexp.Regexp, submatchIdx int, spanType string) []types.Span {
	var result []types.Span
	matches := re.FindAllStringSubmatchIndex(input, -1)

	for _, m := range matches {
		sIdx, eIdx := m[0], m[1]
		if submatchIdx > 0 && len(m) >= (submatchIdx+1)*2 && m[submatchIdx*2] >= 0 {
			sIdx = m[submatchIdx*2]
			eIdx = m[submatchIdx*2+1]
		}
		rStart := len([]rune(input[:sIdx]))
		rEnd := rStart + len([]rune(input[sIdx:eIdx]))
		result = append(result, types.Span{Start: rStart, End: rEnd, Type: spanType})
	}

	return result
}

func mergeSpans(spans []types.Span) []types.Span {
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].Start < spans[j].Start
	})

	merged := []types.Span{spans[0]}
	for i := 1; i < len(spans); i++ {
		curr := spans[i]
		last := &merged[len(merged)-1]

		if curr.Start <= last.End {
			if curr.End > last.End {
				last.End = curr.End
			}
		} else {
			merged = append(merged, curr)
		}
	}
	return merged
}

func isValidLuhn(number string) bool {
	var clean []int
	for _, r := range number {
		if unicode.IsDigit(r) {
			n, _ := strconv.Atoi(string(r))
			clean = append(clean, n)
		}
	}
	if len(clean) < 13 || len(clean) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(clean) - 1; i >= 0; i-- {
		n := clean[i]
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
