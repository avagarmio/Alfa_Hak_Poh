package service

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"llm-proxy/internal/types"
)

// Store — хранилище пар для маскирования/демаскирования. Позволяет подменить
// in-memory кэш общим (Redis) для горизонтального масштабирования.
type Store interface {
	Get(key string) (types.SessionState, bool)
	Set(key string, state types.SessionState)
}

func auditLog(payloadID string, detected []string) {
	slog.Info("pd_masked",
		"payload_id", payloadID,
		"step", "mask",
		"types", detected,
		"count", len(detected),
	)
}

type detector struct {
	re     *regexp.Regexp
	typ    string
	groups []int
}

type Service struct {
	cache          Store
	detectors      []detector
	reCard         *regexp.Regexp
	reCardExpSlash *regexp.Regexp
	reCardExpCtx   *regexp.Regexp
	reFIO          *regexp.Regexp
	reFIOInitialsL *regexp.Regexp
	reFIOInitialsR *regexp.Regexp
	stopTokens     map[string]struct{}
	roleWords      map[string]struct{}
	famousNames    map[string]struct{}
	givenNames     map[string]struct{}
	commonNouns    map[string]struct{}
	weakStop       map[string]struct{}
	composite      bool // составное маскирование: условные типы требуют якоря
}

// compositeRules — условные типы и их «якоря»: тип маскируется только если в
// тексте есть хотя бы один якорь. Применяется лишь при включённом composite.
var compositeRules = map[string][]string{
	"PIN":      {"CARD"},
	"CVV":      {"CARD"},
	"CARD_EXP": {"CARD"},
}

// SetCompositeMasking включает/выключает составное маскирование.
func (s *Service) SetCompositeMasking(on bool) { s.composite = on }

var surnameSuffixes = []string{
	"ова", "ева", "ёва", "ина", "ына", "ская", "цкая",
	"ский", "цкий", "янц", "идзе", "адзе", "швили", "енко",
	"ов", "ев", "ёв", "ин", "ын", "ян", "ко", "ук", "юк", "их", "ых",
}

var patronymicSuffixes = []string{"ович", "евич", "овна", "евна", "инична", "ична"}

func NewService(c Store) *Service {
	s := &Service{cache: c}

	s.detectors = []detector{
		// Контакты
		{re: regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), typ: "EMAIL"},
		{re: regexp.MustCompile(`(?:\+?[78])[\s\-.]*\(?\d{3}\)?[\s\-.]*\d{3}[\s\-.]*\d{2}[\s\-.]*\d{2}`), typ: "PHONE"},

		// Паспорт
		{re: regexp.MustCompile(`(?i)(?:паспорт\s*(?:рф)?[^\d]*?)?(\b\d{2}\s*\d{2}\s*\d{6}\b)`), typ: "PASSPORT", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)сери[ияей]\D{0,4}(\d{2}\s*\d{2})\D{0,10}(?:номер|№)?\s*(\d{6,7}|\d{3}\s\d{3,4})\b`), typ: "PASSPORT", groups: []int{1, 2}},
		{re: regexp.MustCompile(`(?i)(?:паспорт|сери[а-яё]|документ)\D{0,25}(?:номер|№)\s*(\d{6,7})\b`), typ: "PASSPORT", groups: []int{1}},
		{re: regexp.MustCompile(`\b\d{3}-\d{3}\b`), typ: "PASS_CODE"},
		{re: regexp.MustCompile(`(?i)выдан[оаы]?\s+((?:[а-яё]+\s+){0,2}(?:Р[ОУ]ВД|ОВД|ОВМ|У?МВД|ГУВД|ГУ\s?МВД|О?УФМС|ТП)(?:\s+[а-яё]+){0,2})`), typ: "PASS_AUTHORITY", groups: []int{1}},

		// Доп. удостоверения личности: загранпаспорт (серия 2 + номер 7) и СНИЛС
		{re: regexp.MustCompile(`(?i)загран\p{L}*\D{0,20}?(\d{2})\s*(?:№|номер)?\s*(\d{7})\b`), typ: "PASSPORT_INTL", groups: []int{1, 2}},
		{re: regexp.MustCompile(`(?i)снилс\D{0,10}(\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2})`), typ: "SNILS", groups: []int{1}},
		{re: regexp.MustCompile(`\b\d{3}-\d{3}-\d{3}\s\d{2}\b`), typ: "SNILS"},

		// Даты
		{re: regexp.MustCompile(`\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})\b`), typ: "DATE"},
		{re: regexp.MustCompile(`(?i)\b\d{1,2}\s+(?:янв|фев|мар|апр|ма[йя]|июн|июл|авг|сен|окт|ноя|дек)[а-яё]*\.?\s+\d{2,4}(?:\s*г(?:ода|\.)?)?`), typ: "DATE"},
		{re: regexp.MustCompile(`(?i)(?:двадцать|тридцать)?\s*(?:перв|втор|треть|четв[её]рт|пят|шест|седьм|восьм|девят|десят|одиннадцат|двенадцат|тринадцат|четырнадцат|пятнадцат|шестнадцат|семнадцат|восемнадцат|девятнадцат|двадцат|тридцат)[а-яё]*\s+(?:янв|фев|мар|апр|ма[йя]|июн|июл|авг|сен|окт|ноя|дек)[а-яё]*(?:\s+\d{4}(?:\s*г\.?)?|(?:\s+[а-яё]+){1,5}\s+года)?`), typ: "DATE"},

		// Документы
		{re: regexp.MustCompile(`(?i)(?:водительск[а-яё]*|в/у|удостоверени[а-яё]*)[^\d]*?(\b\d{2}\s*(?:\d{2}|[А-ЯA-Z]{2})\s*\d{6}\b)`), typ: "DRIVER", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:инн)[^\d]{0,15}(\d{10}\b|\d{12}\b)`), typ: "INN", groups: []int{1}},

		// Реквизиты карты
		{re: regexp.MustCompile(`(?i)(?:cvv|cvc|код)[^\d]{0,5}(\d{3}\b)`), typ: "CVV", groups: []int{1}},
		// CVV без ключевого слова: 3 цифры сразу после срока действия (MM/YY 876)
		{re: regexp.MustCompile(`(?:0[1-9]|1[0-2])[./\-]\d{2,4}\s+(\d{3})\b`), typ: "CVV", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:пин|pin)(?:[\s\-]?код)?[^\d]{0,12}(\d{4}\b)`), typ: "PIN", groups: []int{1}},
		{re: regexp.MustCompile(`\b([A-Z]{2,}\s+[A-Z]{2,}(?:\s+[A-Z]{2,})?)\b`), typ: "CARD_HOLDER", groups: []int{1}},

		// Место рождения и гражданство
		{re: regexp.MustCompile(`(?i)(?:место\s+рождения|родил(?:ся|ась)\s+в)\s*[:\-]?\s*([^\n,.;]{2,60})`), typ: "BIRTHPLACE", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)гражданств[оа]\s*[:\-]?\s*([^\n,.;]{2,40})`), typ: "CITIZENSHIP", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)гражданин(?:ка)?\s+(РФ|России|Российской\s+Федерации)`), typ: "CITIZENSHIP", groups: []int{1}},

		// Адрес
		{re: regexp.MustCompile(`(?i)индекс\s*[:\-]?\s*(\d{6})`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`\b(\d{6})\s*,\s*(?:г\.|город|обл)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)страна\s*[:\-]?\s*([А-ЯЁ][а-яё]+)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:^|[\s,;:(])(?:г\.\s*|город[а-яё]*\s+)([А-ЯЁ][а-яё\-]+)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:ул\.|улица|пр-?кт\.?|проспект|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная)\s*([^\n,;]{2,40})`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:д\.|дом)\s*(\d+[а-яё]?(?:/\d+)?)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:кв\.|квартира)\s*(\d+)`), typ: "ADDRESS", groups: []int{1}},

		// ФИО по маркерам
		{re: regexp.MustCompile(`(?i)(?:на\s+имя|ф\.?\s?и\.?\s?о\.?)\s*[:\-]?\s+([а-яёa-z]+(?:\s+[а-яёa-z]+){1,2})`), typ: "FIO", groups: []int{1}},
	}

	s.reCard = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

	// Срок действия карты MM/YY. Слэш — сильный признак карты (без контекста);
	// точка/дефис — только рядом с карточным словом. Валидность (текущий месяц
	// или будущее) проверяется в isFutureExpiry.
	s.reCardExpSlash = regexp.MustCompile(`\b(0[1-9]|1[0-2])/(\d{2}|\d{4})\b`)
	s.reCardExpCtx = regexp.MustCompile(`(?i)(?:срок|действ|годн|карт[аеыой]|valid|expir|thru)\D{0,20}?(0[1-9]|1[0-2])[.\-/](\d{2}|\d{4})\b`)

	s.reFIO = regexp.MustCompile(`([А-ЯЁ][а-яё]+)\s+([А-ЯЁ][а-яё]+)(?:\s+([А-ЯЁ][а-яё]+))?(?:\s+([А-ЯЁ][а-яё]+))?`)
	s.reFIOInitialsL = regexp.MustCompile(`[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.\s?[А-ЯЁ]\.`)
	s.reFIOInitialsR = regexp.MustCompile(`[А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+`)

	s.stopTokens = toSet([]string{
		"москва", "россия", "россии", "российская", "российской", "федерация",
		"федерации", "санкт", "петербург", "сити", "банк", "банка", "банке",
		"ао", "оао", "пао", "ооо", "зао", "офис", "отделение", "проспект",
	})
	s.roleWords = toSet([]string{
		"клиент", "клиента", "клиенту", "гражданин", "гражданина", "гражданка",
		"заявитель", "заявителя", "плательщик", "получатель", "держатель",
		"поэт", "писатель", "автор", "господин", "госпожа", "товарищ", "пациент",
		"абонент", "сотрудник", "директор", "менеджер", "президент", "министр",
		"депутат", "уважаемый", "уважаемая", "дорогой", "дорогая",
	})
	s.famousNames = toSet([]string{
		"александр пушкин", "лев толстой", "федор достоевский", "фёдор достоевский",
		"антон чехов", "иван тургенев", "николай гоголь", "михаил лермонтов",
		"сергей есенин", "владимир маяковский", "александр сергеевич пушкин",
	})

	s.givenNames = toSet(expandInflections([]string{
		"александр", "алексей", "анатолий", "андрей", "антон", "аркадий", "артём", "артем",
		"борис", "вадим", "валентин", "валерий", "василий", "виктор", "виталий", "владимир",
		"владислав", "вячеслав", "геннадий", "георгий", "григорий", "даниил", "денис", "дмитрий",
		"евгений", "егор", "иван", "игорь", "илья", "кирилл", "константин", "леонид", "максим",
		"михаил", "никита", "николай", "олег", "павел", "пётр", "петр", "роман", "руслан",
		"сергей", "станислав", "степан", "тимофей", "фёдор", "федор", "эдуард", "юрий", "ярослав",
		"алла", "анастасия", "анна", "валентина", "вера", "виктория", "галина", "дарья", "дина",
		"екатерина", "елена", "ирина", "кристина", "лариса", "любовь", "людмила", "маргарита",
		"марина", "мария", "надежда", "наталья", "наталия", "нина", "оксана", "ольга", "полина",
		"светлана", "софия", "софья", "тамара", "татьяна", "юлия",
	}))

	s.weakStop = toSet([]string{
		"и", "в", "во", "на", "с", "со", "по", "для", "от", "до", "за", "о", "об",
		"у", "к", "из", "а", "но", "же", "ли", "бы", "не", "что", "как", "это",
		"его", "её", "ее", "им", "их", "ему", "ей", "мне", "нам", "вам", "тебе",
		"был", "была", "были", "есть", "сказал", "сказала", "пришёл", "пришла",
	})

	s.commonNouns = toSet([]string{
		"бензин", "магазин", "машина", "картина", "корзина", "причина", "витрина",
		"долина", "вершина", "малина", "рябина", "паутина", "пружина", "калина",
		"година", "равнина", "морщина", "величина", "мужчина", "женщина", "община",
		"молоко", "окно", "далеко", "давно", "число", "слово", "право", "утро",
		"здоров", "готов", "остров", "покров", "улов", "засов", "обзор",
	})

	return s
}

func toSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

func expandInflections(base []string) []string {
	out := make([]string, 0, len(base)*5)
	for _, n := range base {
		out = append(out, n)
		r := []rune(n)
		if len(r) < 3 {
			continue
		}
		stem := string(r[:len(r)-1])
		switch r[len(r)-1] {
		case 'й':
			out = append(out, stem+"я", stem+"ю", stem+"ем", stem+"е")
		case 'а':
			out = append(out, stem+"ы", stem+"е", stem+"у", stem+"ой")
		case 'я':
			out = append(out, stem+"и", stem+"е", stem+"ю", stem+"ей")
		default:
			out = append(out, n+"а", n+"у", n+"ом", n+"е", n+"ым")
		}
	}
	return out
}

// Стратегии маскирования на уровне системы-потребителя.
const (
	StrategyToken     = "token"     // [FIO_1] — обратимо через mapping (по умолчанию)
	StrategyAsterisks = "asterisks" // банковский стиль **** — восстановление из кэша
	StrategySynthetic = "synthetic" // правдоподобные фейки (обратимо через mapping)
)

type ProcessOptions struct {
	MaskTypes     map[string]struct{}
	DemaskEnabled bool
	Strategy      string // "" == StrategyToken
}

func DefaultOptions() ProcessOptions {
	return ProcessOptions{MaskTypes: nil, DemaskEnabled: true, Strategy: StrategyToken}
}

func (s *Service) Process(req types.ProcessRequest, opts ProcessOptions) string {
	state, exists := s.cache.Get(req.PayloadID)

	if !exists {
		var masked string
		var detected []string
		var mapping map[string]string
		switch opts.Strategy {
		case StrategyAsterisks:
			masked, detected = s.MaskAsterisks(req.Payload, opts.MaskTypes)
		case StrategySynthetic:
			masked, detected, mapping = s.MaskSynthetic(req.Payload, opts.MaskTypes)
		default:
			masked, detected, mapping = s.Mask(req.Payload, opts.MaskTypes)
		}
		s.cache.Set(req.PayloadID, types.SessionState{
			OriginalText: req.Payload,
			MaskedText:   masked,
			Mapping:      mapping,
		})
		auditLog(req.PayloadID, detected)
		return masked
	}

	// Идемпотентный ретрай прямого шага
	if req.Payload == state.OriginalText {
		return state.MaskedText
	}

	// Обратный шаг (демаскирование)
	if !opts.DemaskEnabled {
		return req.Payload
	}
	if len(state.Mapping) == 0 {
		// Стратегия без mapping (звёздочки): восстанавливаем оригинал из кэша,
		// когда пришла ранее выданная маска.
		if req.Payload == state.MaskedText {
			return state.OriginalText
		}
		return req.Payload
	}
	return s.Demask(req.Payload, state.Mapping)
}

func (s *Service) Demask(input string, mapping map[string]string) string {
	if len(mapping) == 0 || input == "" {
		return input
	}
	// Заменяем более длинные плейсхолдеры/фейки раньше коротких, чтобы короткий
	// фейк (напр. CVV «123») не совпал с частью длинного (номер карты).
	keys := make([]string, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	pairs := make([]string, 0, len(mapping)*2)
	for _, k := range keys {
		pairs = append(pairs, k, mapping[k])
	}
	return strings.NewReplacer(pairs...).Replace(input)
}

func allow(set map[string]struct{}, typ string) bool {
	if set == nil {
		return true
	}
	_, ok := set[typ]
	return ok
}

func (s *Service) Mask(input string, allowed map[string]struct{}) (string, []string, map[string]string) {
	if input == "" {
		return input, nil, nil
	}

	spans, detected := s.collectSpans(input, allowed)
	if len(spans) == 0 {
		return input, nil, nil
	}

	var sb strings.Builder
	sb.Grow(len(input))

	mapping := make(map[string]string)
	counters := make(map[string]int)
	lastIdx := 0

	for _, span := range spans {
		if span.Start < lastIdx {
			continue
		}
		sb.WriteString(input[lastIdx:span.Start])

		counters[span.Type]++
		placeholder := fmt.Sprintf("[%s_%d]", span.Type, counters[span.Type])
		mapping[placeholder] = input[span.Start:span.End]

		sb.WriteString(placeholder)
		lastIdx = span.End
	}
	sb.WriteString(input[lastIdx:])

	return sb.String(), detected, mapping
}

// MaskSynthetic заменяет ПД правдоподобными фейковыми значениями по типу.
// Обратимость — через mapping (фейк -> оригинал). Фейки уникальны в пределах
// запроса; для типов без генератора используется плейсхолдер [TYPE_N].
func (s *Service) MaskSynthetic(input string, allowed map[string]struct{}) (string, []string, map[string]string) {
	if input == "" {
		return input, nil, nil
	}

	spans, detected := s.collectSpans(input, allowed)
	if len(spans) == 0 {
		return input, nil, nil
	}

	var sb strings.Builder
	sb.Grow(len(input))

	mapping := make(map[string]string)
	counters := make(map[string]int)
	used := make(map[string]bool)
	lastIdx := 0

	for _, span := range spans {
		if span.Start < lastIdx {
			continue
		}
		sb.WriteString(input[lastIdx:span.Start])

		original := input[span.Start:span.End]
		counters[span.Type]++
		fake := s.synthValue(span.Type, original, counters[span.Type], used)
		used[fake] = true
		mapping[fake] = original

		sb.WriteString(fake)
		lastIdx = span.End
	}
	sb.WriteString(input[lastIdx:])

	return sb.String(), detected, mapping
}

var (
	synthLast  = []string{"Смирнов", "Кузнецов", "Попов", "Соколов", "Лебедев", "Козлов", "Новиков", "Морозов", "Волков", "Зайцев"}
	synthFirst = []string{"Пётр", "Иван", "Сергей", "Алексей", "Дмитрий", "Николай", "Андрей", "Михаил", "Егор", "Роман"}
	synthPatr  = []string{"Петрович", "Иванович", "Сергеевич", "Алексеевич", "Дмитриевич", "Николаевич"}
	synthCity  = []string{"Кленовая", "Садовая", "Гагарина", "Мира", "Заречная", "Полевая", "Лесная", "Центральная"}
)

// synthValue генерирует уникальный правдоподобный фейк для типа typ.
func (s *Service) synthValue(typ, original string, counter int, used map[string]bool) string {
	for attempt := 0; ; attempt++ {
		n := counter + attempt
		var v string
		switch typ {
		case "FIO":
			words := len(strings.Fields(original))
			last := synthLast[n%len(synthLast)]
			first := synthFirst[(n/len(synthLast))%len(synthFirst)]
			switch {
			case words <= 1:
				v = last
			case words == 2:
				v = last + " " + first
			default:
				v = last + " " + first + " " + synthPatr[n%len(synthPatr)]
			}
		case "PHONE":
			v = fmt.Sprintf("+7 9%02d %03d-%02d-%02d", n%100, (n*7)%1000, n%100, (n*3)%100)
		case "EMAIL":
			v = fmt.Sprintf("user%d@example.com", n)
		case "CARD":
			v = synthCard(n)
		case "CARD_EXP":
			v = fmt.Sprintf("%02d/%02d", n%12+1, 30+n%9)
		case "CVV":
			v = fmt.Sprintf("%03d", 100+n%900)
		case "PIN":
			v = fmt.Sprintf("%04d", 1000+n%9000)
		case "DATE":
			v = fmt.Sprintf("%02d.%02d.19%02d", n%28+1, n%12+1, 60+n%39)
		case "PASSPORT":
			v = fmt.Sprintf("%02d %02d %06d", 40+n%50, 10+n%89, (n*137)%1000000)
		case "PASSPORT_INTL":
			v = fmt.Sprintf("%02d %07d", 70+n%9, (n*911)%10000000)
		case "SNILS":
			v = fmt.Sprintf("%03d-%03d-%03d %02d", n%1000, (n*3)%1000, (n*7)%1000, n%100)
		case "INN":
			v = fmt.Sprintf("%012d", int64(n)*104729%1000000000000)
		case "PASS_CODE":
			v = fmt.Sprintf("%03d-%03d", n%1000, (n*5)%1000)
		case "CARD_HOLDER":
			v = []string{"IVAN PETROV", "PETR SMIRNOV", "SERGEI VOLKOV", "ROMAN KOZLOV"}[n%4]
		case "ADDRESS":
			if isAllDigits(original) {
				v = fmt.Sprintf("%0*d", len(original), (n*7)%pow10(len(original)))
			} else {
				v = synthCity[n%len(synthCity)]
			}
		case "CITIZENSHIP":
			v = []string{"РФ", "России", "Российской Федерации"}[n%3]
		case "BIRTHPLACE":
			v = []string{"Тула", "Рязань", "Калуга", "Тверь"}[n%4]
		default:
			// Нет генератора — обратимый плейсхолдер.
			v = fmt.Sprintf("[%s_%d]", typ, counter)
		}
		if !used[v] {
			return v
		}
	}
}

// synthCard генерирует валидный по Луну 16-значный номер из счётчика.
func synthCard(n int) string {
	base := fmt.Sprintf("4%014d", n%100000000000000) // 15 цифр (Visa-like)
	full := base + strconv.Itoa(luhnCheckDigit(base))
	return full[0:4] + " " + full[4:8] + " " + full[8:12] + " " + full[12:16]
}

func luhnCheckDigit(num string) int {
	sum, alt := 0, true
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return (10 - sum%10) % 10
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func pow10(n int) int {
	p := 1
	for i := 0; i < n && i < 9; i++ {
		p *= 10
	}
	return p
}

func (s *Service) MaskAsterisks(input string, allowed map[string]struct{}) (string, []string) {
	if input == "" {
		return input, nil
	}

	spans, detected := s.collectSpans(input, allowed)
	if len(spans) == 0 {
		return input, nil
	}

	var sb strings.Builder
	sb.Grow(len(input))
	lastIdx := 0

	for _, span := range spans {
		if span.Start < lastIdx {
			continue
		}
		sb.WriteString(input[lastIdx:span.Start])

		spanBytes := input[span.Start:span.End]
		runes := []rune(spanBytes)
		rLen := len(runes)

		for i, r := range runes {
			if unicode.IsSpace(r) || r == '-' || r == '.' || r == '@' || r == '+' {
				sb.WriteRune(r)
			} else if rLen > 4 && (i == 0 || i == rLen-1) {
				sb.WriteRune(r)
			} else {
				sb.WriteRune('*')
			}
		}
		lastIdx = span.End
	}
	sb.WriteString(input[lastIdx:])

	return sb.String(), detected
}

func (s *Service) collectSpans(input string, allowed map[string]struct{}) ([]types.Span, []string) {
	var spans []types.Span

	for _, d := range s.detectors {
		if !allow(allowed, d.typ) {
			continue
		}
		spans = append(spans, s.findSpans(input, d.re, d.typ, d.groups...)...)
	}

	if allow(allowed, "CARD") {
		for _, match := range s.reCard.FindAllStringIndex(input, -1) {
			seg := input[match[0]:match[1]]
			if isValidLuhn(seg) {
				spans = append(spans, types.Span{Start: match[0], End: match[1], Type: "CARD"})
			} else if end, ok := longestLuhnCard(seg); ok {
				// Жадный матч мог прихватить лишние цифры (напр. месяц из «12/36»)
				// — маскируем самый длинный валидный по Луну префикс.
				spans = append(spans, types.Span{Start: match[0], End: match[0] + end, Type: "CARD"})
			}
		}
	}

	// Срок действия карты — только валидные (текущий месяц/будущее)
	if allow(allowed, "CARD_EXP") {
		now := time.Now()
		for _, re := range []*regexp.Regexp{s.reCardExpSlash, s.reCardExpCtx} {
			for _, m := range re.FindAllStringSubmatchIndex(input, -1) {
				mm, _ := strconv.Atoi(input[m[2]:m[3]])
				yy, _ := strconv.Atoi(input[m[4]:m[5]])
				if isFutureExpiry(mm, yy, now) {
					spans = append(spans, types.Span{Start: m[2], End: m[5], Type: "CARD_EXP"})
				}
			}
		}
	}

	if allow(allowed, "FIO") {
		spans = append(spans, s.findFIO(input)...)
		spans = append(spans, s.findFIOMorph(input)...)
	}

	if s.composite {
		spans = s.filterComposite(input, spans)
	}

	if len(spans) == 0 {
		return nil, nil
	}

	detected := uniqueTypes(spans)
	spans = mergeSpans(spans)
	return spans, detected
}

var reCardWord = regexp.MustCompile(`(?i)карт[аеыуой]`)

// filterComposite убирает спаны условных типов, у которых в тексте нет якоря
// (напр. PIN без CARD). Проверка на уровне всего текста, не по близости.
// Якорь CARD считается присутствующим при валидной карте, любом карто-подобном
// номере (13–19 цифр) или слове «карт…» — чтобы не терять маску из-за невалидной
// по Луну карты.
func (s *Service) filterComposite(input string, spans []types.Span) []types.Span {
	present := make(map[string]bool, len(spans))
	for _, sp := range spans {
		present[sp.Type] = true
	}
	if !present["CARD"] && (s.reCard.MatchString(input) || reCardWord.MatchString(input)) {
		present["CARD"] = true
	}
	out := spans[:0]
	for _, sp := range spans {
		if anchors, ok := compositeRules[sp.Type]; ok {
			keep := false
			for _, a := range anchors {
				if present[a] {
					keep = true
					break
				}
			}
			if !keep {
				continue
			}
		}
		out = append(out, sp)
	}
	return out
}

type fioToken struct {
	start, end int
	low        string
}

func (s *Service) classifyName(low string) (nameLike, strong bool) {
	if s.inSet(s.commonNouns, low) {
		return false, false
	}
	if s.inSet(s.givenNames, low) {
		return true, true
	}
	if isPatronymic(low) {
		return true, true
	}
	if utf8.RuneCountInString(low) >= 5 && hasAnySuffix(low, surnameSuffixes) {
		return true, false
	}
	return false, false
}

func isPatronymic(low string) bool {
	return utf8.RuneCountInString(low) >= 5 && hasAnySuffix(low, patronymicSuffixes)
}

func (s *Service) disqualified(low string) bool {
	return s.inSet(s.commonNouns, low) || s.inSet(s.weakStop, low) ||
		s.inSet(s.roleWords, low) || s.inSet(s.stopTokens, low)
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func tokenizeWords(s string) []fioToken {
	var tokens []fioToken
	inWord := false
	start := 0

	for i, r := range s {
		if unicode.IsLetter(r) {
			if !inWord {
				inWord = true
				start = i
			}
		} else {
			if inWord {
				tokens = append(tokens, fioToken{
					start: start,
					end:   i,
					low:   strings.ToLower(s[start:i]),
				})
				inWord = false
			}
		}
	}
	if inWord {
		tokens = append(tokens, fioToken{
			start: start,
			end:   len(s),
			low:   strings.ToLower(s[start:]),
		})
	}
	return tokens
}

func (s *Service) findFIOMorph(input string) []types.Span {
	tokens := tokenizeWords(input)
	if len(tokens) == 0 {
		return nil
	}

	var result []types.Span
	i := 0
	for i < len(tokens) {
		matched := false
		for w := 3; w >= 1; w-- {
			if i+w > len(tokens) {
				continue
			}
			if !adjacentTokens(input, tokens, i, i+w-1) {
				continue
			}

			nameLike, strong := 0, 0
			for k := 0; k < w; k++ {
				nl, st := s.classifyName(tokens[i+k].low)
				if nl {
					nameLike++
				}
				if st {
					strong++
				}
			}

			ok := false
			if w >= 2 {
				ok = nameLike == w && strong >= 1
				if !ok && w == 3 && strong >= 1 {
					nl0, _ := s.classifyName(tokens[i].low)
					nl2, _ := s.classifyName(tokens[i+2].low)
					if nl0 && nl2 && !s.disqualified(tokens[i+1].low) {
						ok = true
					}
				}
			} else {
				ok = isPatronymic(tokens[i].low)
			}

			if ok && !s.morphIsFalse(tokens[i:i+w]) {
				result = append(result, types.Span{
					Start: tokens[i].start,
					End:   tokens[i+w-1].end,
					Type:  "FIO",
				})
				i += w
				matched = true
				break
			}
		}
		if !matched {
			i++
		}
	}
	return result
}

func adjacentTokens(input string, tokens []fioToken, from, to int) bool {
	for k := from; k < to; k++ {
		gap := input[tokens[k].end:tokens[k+1].start]
		if len(gap) == 0 || len(gap) > 3 {
			return false
		}
		for i := 0; i < len(gap); i++ {
			b := gap[i]
			if b != ' ' && b != '\t' && b != '-' {
				return false
			}
		}
	}
	return true
}

func (s *Service) morphIsFalse(tokens []fioToken) bool {
	for _, t := range tokens {
		if s.inSet(s.stopTokens, t.low) {
			return true
		}
	}
	if len(tokens) >= 2 {
		k1 := tokens[0].low + " " + tokens[1].low
		if s.inSet(s.famousNames, k1) {
			return true
		}
		k2 := tokens[1].low + " " + tokens[0].low
		if s.inSet(s.famousNames, k2) {
			return true
		}
		if len(tokens) == 3 {
			k3 := tokens[0].low + " " + tokens[1].low + " " + tokens[2].low
			if s.inSet(s.famousNames, k3) {
				return true
			}
		}
	}
	return false
}

func (s *Service) findFIO(input string) []types.Span {
	var result []types.Span

	for _, m := range s.reFIO.FindAllStringSubmatchIndex(input, -1) {
		if m[0] > 0 && input[m[0]-1] == '.' {
			continue
		}

		var toks []fioToken
		for g := 1; g <= 4; g++ {
			a, b := m[2*g], m[2*g+1]
			if a >= 0 {
				toks = append(toks, fioToken{start: a, end: b, low: strings.ToLower(input[a:b])})
			}
		}

		i := 0
		for i < len(toks) && s.inSet(s.roleWords, toks[i].low) {
			i++
		}
		core := toks[i:]
		if len(core) < 2 {
			continue
		}

		if s.coreIsFalse(core) {
			continue
		}

		result = append(result, types.Span{
			Start: core[0].start,
			End:   core[len(core)-1].end,
			Type:  "FIO",
		})
	}

	for _, re := range []*regexp.Regexp{s.reFIOInitialsL, s.reFIOInitialsR} {
		for _, m := range re.FindAllStringIndex(input, -1) {
			result = append(result, types.Span{
				Start: m[0],
				End:   m[1],
				Type:  "FIO",
			})
		}
	}

	return result
}

func (s *Service) coreIsFalse(core []fioToken) bool {
	for _, t := range core {
		if s.inSet(s.stopTokens, t.low) {
			return true
		}
	}
	if len(core) >= 2 {
		k1 := core[0].low + " " + core[1].low
		if s.inSet(s.famousNames, k1) {
			return true
		}

		k2 := core[1].low + " " + core[0].low
		if s.inSet(s.famousNames, k2) {
			return true
		}

		if len(core) == 3 {
			k3 := core[0].low + " " + core[1].low + " " + core[2].low
			if s.inSet(s.famousNames, k3) {
				return true
			}
		}

	}
	return false
}

func (s *Service) inSet(set map[string]struct{}, key string) bool {
	_, ok := set[key]

	return ok
}

func (s *Service) findSpans(input string, re *regexp.Regexp, spanType string, groups ...int) []types.Span {
	var result []types.Span
	matches := re.FindAllStringSubmatchIndex(input, -1)

	for _, m := range matches {
		if len(groups) == 0 {
			result = append(result, types.Span{Start: m[0], End: m[1], Type: spanType})
			continue
		}
		for _, g := range groups {
			if len(m) >= (g+1)*2 && m[g*2] >= 0 {
				result = append(result, types.Span{Start: m[g*2], End: m[g*2+1], Type: spanType})
			}
		}
	}
	return result
}

func uniqueTypes(spans []types.Span) []string {
	seen := make(map[string]struct{}, len(spans))
	var out []string
	for _, sp := range spans {
		if _, ok := seen[sp.Type]; !ok {
			seen[sp.Type] = struct{}{}
			out = append(out, sp.Type)
		}
	}
	sort.Strings(out)
	return out
}

func mergeSpans(spans []types.Span) []types.Span {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start == spans[j].Start {
			return spans[i].End > spans[j].End
		}
		return spans[i].Start < spans[j].Start
	})

	merged := make([]types.Span, 0, len(spans))
	merged = append(merged, spans[0])

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

// isFutureExpiry проверяет, что срок действия (MM, YY|YYYY) — текущий месяц или
// будущее. Двузначный год трактуется как 20YY. Просроченные/невалидные — нет.
func isFutureExpiry(mm, yy int, now time.Time) bool {
	if mm < 1 || mm > 12 {
		return false
	}
	if yy < 100 {
		yy += 2000
	}
	if yy != now.Year() {
		return yy > now.Year()
	}
	return mm >= int(now.Month())
}

// longestLuhnCard возвращает байтовую длину самого длинного валидного по Луну
// префикса карты внутри seg (только цифры/пробелы/дефисы). Нужно, когда жадный
// матч прихватил соседние цифры (срок действия и т.п.).
func longestLuhnCard(seg string) (int, bool) {
	digits := make([]int, 0, len(seg))
	ends := make([]int, 0, len(seg))
	for i := 0; i < len(seg); i++ {
		if b := seg[i]; b >= '0' && b <= '9' {
			digits = append(digits, int(b-'0'))
			ends = append(ends, i+1)
		}
	}
	maxL := len(digits)
	if maxL > 19 {
		maxL = 19
	}
	for L := maxL; L >= 13; L-- {
		if luhnOnDigits(digits[:L]) {
			return ends[L-1], true
		}
	}
	return 0, false
}

func luhnOnDigits(ds []int) bool {
	sum := 0
	alt := false
	for i := len(ds) - 1; i >= 0; i-- {
		n := ds[i]
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func isValidLuhn(number string) bool {
	sum := 0
	alt := false
	digitsCount := 0

	for i := len(number) - 1; i >= 0; i-- {
		b := number[i]
		if b >= '0' && b <= '9' {
			n := int(b - '0')
			digitsCount++
			if alt {
				n *= 2
				if n > 9 {
					n -= 9
				}
			}
			sum += n
			alt = !alt
		} else if b != ' ' && b != '-' {
			return false
		}
	}

	return digitsCount >= 13 && digitsCount <= 19 && sum%10 == 0
}
