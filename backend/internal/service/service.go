package service

import (
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"llm-proxy/internal/repository/cache"
	"llm-proxy/internal/types"
)

// auditLog пишет аудит-запись о найденных типах ПД. Значения ПД никогда не
// попадают в лог — только payload_id, этап и перечень типов.
func auditLog(payloadID string, detected []string) {
	slog.Info("pd_masked",
		"payload_id", payloadID,
		"step", "mask",
		"types", detected,
		"count", len(detected),
	)
}

// detector — regexp-правило детекции ПД. groups задаёт номера групп захвата,
// которые нужно маскировать; пустой groups означает «весь матч».
// Новые типы ПД добавляются как элементы s.detectors без правки ядра маскирования.
type detector struct {
	re     *regexp.Regexp
	typ    string
	groups []int
}

type Service struct {
	cache          *cache.ShardedCache
	detectors      []detector
	reCard         *regexp.Regexp
	reFIO          *regexp.Regexp
	reFIOInitialsL *regexp.Regexp
	reFIOInitialsR *regexp.Regexp
	reWord         *regexp.Regexp
	stopTokens     map[string]struct{}
	roleWords      map[string]struct{}
	famousNames    map[string]struct{}
	givenNames     map[string]struct{}
	commonNouns    map[string]struct{}
	weakStop       map[string]struct{}
}

// surnameSuffixes — характерные окончания русских/кавказских/украинских фамилий.
// Слабый сигнал: сам по себе НЕ срабатывает (ср. «бензин», «молоко»), только в
// связке с сильным якорем (словарное имя или отчество).
var surnameSuffixes = []string{
	"ова", "ева", "ёва", "ина", "ына", "ская", "цкая",
	"ский", "цкий", "янц", "идзе", "адзе", "швили", "енко",
	"ов", "ев", "ёв", "ин", "ын", "ян", "ко", "ук", "юк", "их", "ых",
}

// patronymicSuffixes — окончания отчеств. Сильный якорь: слова на -ович/-евич/
// -овна/-евна/-ична почти всегда отчества.
var patronymicSuffixes = []string{"ович", "евич", "овна", "евна", "инична", "ична"}

func NewService(c *cache.ShardedCache) *Service {
	s := &Service{cache: c}

	s.detectors = []detector{
		// Контакты
		{re: regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), typ: "EMAIL"},
		{re: regexp.MustCompile(`(?:\+?[78])[\s\-.]*\(?\d{3}\)?[\s\-.]*\d{3}[\s\-.]*\d{2}[\s\-.]*\d{2}`), typ: "PHONE"},

		// Паспорт: слитно (4509 123456) и с разделителями (серия 4509 номер 123456)
		{re: regexp.MustCompile(`(?i)(?:паспорт\s*(?:рф)?[^\d]*?)?(\b\d{2}\s*\d{2}\s*\d{6}\b)`), typ: "PASSPORT", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)серия\D{0,4}(\d{2}\s*\d{2})\D{0,10}(\d{6,7})\b`), typ: "PASSPORT", groups: []int{1, 2}},
		{re: regexp.MustCompile(`(?i)(?:паспорт|сери[а-яё]|документ)\D{0,25}(?:номер|№)\s*(\d{6,7})\b`), typ: "PASSPORT", groups: []int{1}},
		{re: regexp.MustCompile(`\b\d{3}-\d{3}\b`), typ: "PASS_CODE"},
		// Орган, выдавший паспорт: якорь «выдан», маскируется орган после него
		// (само слово «выдан» остаётся). Ловит «Первомайским РУВД», «ОВД Тверского».
		{re: regexp.MustCompile(`(?i)выдан[оаы]?\s+((?:[а-яё]+\s+){0,2}(?:Р[ОУ]ВД|ОВД|ОВМ|У?МВД|ГУВД|ГУ\s?МВД|О?УФМС|ТП)(?:\s+[а-яё]+){0,2})`), typ: "PASS_AUTHORITY", groups: []int{1}},

		// Даты: числовые (любой порядок), текстовые с цифровым днём и полностью прописью
		{re: regexp.MustCompile(`\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})\b`), typ: "DATE"},
		{re: regexp.MustCompile(`(?i)\b\d{1,2}\s+(?:январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр)[а-яё]*\s+\d{2,4}(?:\s*г(?:ода|\.)?)?`), typ: "DATE"},
		{re: regexp.MustCompile(`(?i)(?:двадцать|тридцать)?\s*(?:перв|втор|треть|четв[её]рт|пят|шест|седьм|восьм|девят|десят|одиннадцат|двенадцат|тринадцат|четырнадцат|пятнадцат|шестнадцат|семнадцат|восемнадцат|девятнадцат|двадцат|тридцат)[а-яё]*\s+(?:январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр)[а-яё]*(?:\s+\d{4}(?:\s*г\.?)?|(?:\s+[а-яё]+){1,5}\s+года)?`), typ: "DATE"},

		// Документы
		{re: regexp.MustCompile(`(?i)(?:водительск[а-яё]*|в/у|удостоверени[а-яё]*)[^\d]*?(\b\d{2}\s*(?:\d{2}|[А-ЯA-Z]{2})\s*\d{6}\b)`), typ: "DRIVER", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:инн)[^\d]{1,5}(\b\d{10}\b|\b\d{12}\b)`), typ: "INN", groups: []int{1}},

		// Реквизиты карты
		{re: regexp.MustCompile(`(?i)(?:cvv|cvc|код)[^\d]{1,5}(\b\d{3}\b)`), typ: "CVV", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:пин|pin)(?:[\s\-]?код)?[^\d]{0,12}(\b\d{4}\b)`), typ: "PIN", groups: []int{1}},
		// Имя держателя карты (латиница)
		{re: regexp.MustCompile(`\b([A-Z]{2,}\s+[A-Z]{2,}(?:\s+[A-Z]{2,})?)\b`), typ: "CARD_HOLDER", groups: []int{1}},

		// Место рождения и гражданство (контекстные маркеры)
		{re: regexp.MustCompile(`(?i)(?:место\s+рождения|родил(?:ся|ась)\s+в)\s*[:\-]?\s*([^\n,.;]{2,60})`), typ: "BIRTHPLACE", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)гражданств[оа]\s*[:\-]?\s*([^\n,.;]{2,40})`), typ: "CITIZENSHIP", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)гражданин(?:ка)?\s+(РФ|России|Российской\s+Федерации)`), typ: "CITIZENSHIP", groups: []int{1}},

		// Адрес: индекс, страна, город, улица, дом, квартира
		{re: regexp.MustCompile(`(?i)индекс\s*[:\-]?\s*(\d{6})`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`\b(\d{6})\s*,\s*(?:г\.|город|обл)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)страна\s*[:\-]?\s*([А-ЯЁ][а-яё]+)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:г\.|город)\s*([А-ЯЁ][а-яё\-]+)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:ул\.|улица|пр-?кт\.?|проспект|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная)\s*([^\n,;]{2,40})`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:д\.|дом)\s*(\d+[а-яё]?(?:/\d+)?)`), typ: "ADDRESS", groups: []int{1}},
		{re: regexp.MustCompile(`(?i)(?:кв\.|квартира)\s*(\d+)`), typ: "ADDRESS", groups: []int{1}},

		// ФИО после сильных маркеров (регистронезависимо)
		{re: regexp.MustCompile(`(?i)(?:на\s+имя|ф\.?\s?и\.?\s?о\.?)\s*[:\-]?\s+([а-яёa-z]+(?:\s+[а-яёa-z]+){1,2})`), typ: "FIO", groups: []int{1}},
	}

	// Карта — только с проверкой Луна
	s.reCard = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

	// ФИО: капитализированное (до 4 слов, чтобы поглотить ведущую роль +
	// фамилия/имя/отчество) и инициалы. \b вокруг кириллицы в RE2 не работает
	// (ASCII-граница), поэтому здесь его нет.
	s.reFIO = regexp.MustCompile(`([А-ЯЁ][а-яё]+)\s+([А-ЯЁ][а-яё]+)(?:\s+([А-ЯЁ][а-яё]+))?(?:\s+([А-ЯЁ][а-яё]+))?`)
	s.reFIOInitialsL = regexp.MustCompile(`[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.\s?[А-ЯЁ]\.`) // Иванов И.И.
	s.reFIOInitialsR = regexp.MustCompile(`[А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+`) // И.И. Иванов

	// Стоп-токены: если слово в имени совпадает с ними — это не ПД (топонимы, юрлица)
	s.stopTokens = toSet([]string{
		"москва", "россия", "россии", "российская", "российской", "федерация",
		"федерации", "санкт", "петербург", "сити", "банк", "банка", "банке",
		"ао", "оао", "пао", "ооо", "зао", "офис", "отделение", "проспект",
	})
	// Ролевые слова: срезаются в начале ФИО (маскируем имя, но не роль)
	s.roleWords = toSet([]string{
		"клиент", "клиента", "клиенту", "гражданин", "гражданина", "гражданка",
		"заявитель", "заявителя", "плательщик", "получатель", "держатель",
		"поэт", "писатель", "автор", "господин", "госпожа", "товарищ", "пациент",
		"абонент", "сотрудник", "директор", "менеджер", "президент", "министр",
		"депутат", "уважаемый", "уважаемая", "дорогой", "дорогая",
	})
	// Известные публичные личности — не ПД
	s.famousNames = toSet([]string{
		"александр пушкин", "лев толстой", "федор достоевский", "фёдор достоевский",
		"антон чехов", "иван тургенев", "николай гоголь", "михаил лермонтов",
		"сергей есенин", "владимир маяковский", "александр сергеевич пушкин",
	})

	// Токенизатор слов (только буквы) для морфологического детектора ФИО.
	s.reWord = regexp.MustCompile(`[А-Яа-яЁё]+`)

	// Словарь распространённых имён + их падежные формы — сильный якорь
	// (регистронезависимо). Формы генерируются, чтобы ловить «для сергея», «ивану».
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

	// Частотные служебные слова: дисквалифицируют токен в «мостике» ФИО,
	// не давая захватить «сказал ему петрович».
	s.weakStop = toSet([]string{
		"и", "в", "во", "на", "с", "со", "по", "для", "от", "до", "за", "о", "об",
		"у", "к", "из", "а", "но", "же", "ли", "бы", "не", "что", "как", "это",
		"его", "её", "ее", "им", "их", "ему", "ей", "мне", "нам", "вам", "тебе",
		"был", "была", "были", "есть", "сказал", "сказала", "пришёл", "пришла",
	})

	// Общеупотребимые слова с «фамильными» окончаниями — не ПД (ср. бензИН, молокО).
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

// expandInflections добавляет к каждому имени его основные падежные формы,
// чтобы словарь ловил «сергея», «ивану», «анне» без опоры на именительный падеж.
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
		case 'й': // Сергей -> Сергея/Сергею/Сергеем
			out = append(out, stem+"я", stem+"ю", stem+"ем", stem+"е")
		case 'а': // Анна -> Анны/Анне/Анну/Анной
			out = append(out, stem+"ы", stem+"е", stem+"у", stem+"ой")
		case 'я': // Мария -> Марии/Марию/Марией
			out = append(out, stem+"и", stem+"е", stem+"ю", stem+"ей")
		default: // Иван -> Ивана/Ивану/Иваном/Иване
			out = append(out, n+"а", n+"у", n+"ом", n+"е", n+"ым")
		}
	}
	return out
}

// ProcessOptions задаёт правила обработки в разрезе системы-потребителя.
// MaskTypes == nil означает «маскировать все типы».
type ProcessOptions struct {
	MaskTypes     map[string]struct{}
	DemaskEnabled bool
}

// DefaultOptions — поведение без контроля доступа: маскируем всё, демаск включён.
func DefaultOptions() ProcessOptions {
	return ProcessOptions{MaskTypes: nil, DemaskEnabled: true}
}

// Process координирует шаги маскирования, демаскирования и ретраев.
func (s *Service) Process(req types.ProcessRequest, opts ProcessOptions) string {
	state, exists := s.cache.Get(req.PayloadID)

	if !exists {
		// Прямой шаг: новое значение payload_id -> маскируем и кэшируем
		masked, detected := s.Mask(req.Payload, opts.MaskTypes)
		s.cache.Set(req.PayloadID, types.SessionState{
			OriginalText: req.Payload,
			MaskedText:   masked,
		})
		auditLog(req.PayloadID, detected)
		return masked
	}

	// Идемпотентный ретрай маскирования
	if req.Payload == state.OriginalText {
		return state.MaskedText
	}

	// Обратный шаг (демаскирование): пришёл ранее замаскированный текст.
	// Если демаскирование для системы выключено — не раскрываем оригинал.
	if !opts.DemaskEnabled {
		return req.Payload
	}
	return state.OriginalText
}

// allow сообщает, нужно ли применять детектор типа typ. nil-набор = все типы.
func allow(set map[string]struct{}, typ string) bool {
	if set == nil {
		return true
	}
	_, ok := set[typ]
	return ok
}

// buildRuneIndex за один проход строит срез рун и карту «байт-офсет → руна».
// Это убирает O(n^2) на больших текстах: конвертация офсета матча в рунную
// позицию становится O(1) вместо повторного len([]rune(input[:i])).
func buildRuneIndex(input string) ([]rune, []int) {
	runes := make([]rune, 0, len(input))
	b2r := make([]int, len(input)+1)
	ri := 0
	for bp, r := range input {
		b2r[bp] = ri
		runes = append(runes, r)
		ri++
	}
	b2r[len(input)] = ri
	return runes, b2r
}

// Mask находит и маскирует ПД с сохранением разделителей и структуры.
// allowed ограничивает набор маскируемых типов (nil = все).
// Возвращает результат и отсортированный список уникальных найденных типов ПД.
func (s *Service) Mask(input string, allowed map[string]struct{}) (string, []string) {
	if input == "" {
		return input, nil
	}
	runes, b2r := buildRuneIndex(input)
	var spans []types.Span

	for _, d := range s.detectors {
		if !allow(allowed, d.typ) {
			continue
		}
		spans = append(spans, s.findSpans(input, b2r, d.re, d.typ, d.groups...)...)
	}

	// Карты с обязательной проверкой контрольной суммы Луна
	if allow(allowed, "CARD") {
		for _, match := range s.reCard.FindAllStringIndex(input, -1) {
			if isValidLuhn(input[match[0]:match[1]]) {
				spans = append(spans, runeSpan(b2r, match[0], match[1], "CARD"))
			}
		}
	}

	if allow(allowed, "FIO") {
		spans = append(spans, s.findFIO(input, b2r)...)
		spans = append(spans, s.findFIOMorph(input, b2r)...)
	}

	if len(spans) == 0 {
		return input, nil
	}

	detected := uniqueTypes(spans)
	spans = mergeSpans(spans)

	out := make([]rune, len(runes))
	copy(out, runes)

	for _, span := range spans {
		length := span.End - span.Start
		for i := span.Start; i < span.End && i < len(out); i++ {
			// Сохраняем форматирующие знаки
			if unicode.IsSpace(out[i]) || out[i] == '-' || out[i] == '.' || out[i] == '@' || out[i] == '+' {
				continue
			}
			// Для длинных сущностей оставляем края (банковский стандарт)
			if length > 4 {
				if i == span.Start || i == span.End-1 {
					continue
				}
			}
			out[i] = '*'
		}
	}

	return string(out), detected
}

type fioToken struct {
	start, end int
	low        string
}

// classifyName оценивает слово как часть ФИО (регистронезависимо):
//   - nameLike: слово похоже на элемент имени;
//   - strong:   сильный якорь (словарное имя или отчество) — только он даёт
//     право срабатыванию; слабое фамильное окончание само по себе не считается.
//
// Общеупотребимые слова (бензин, магазин, …) исключаются в первую очередь.
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
	// Фамильное окончание — слабый сигнал, только для слов длиной >= 5.
	if len([]rune(low)) >= 5 && hasAnySuffix(low, surnameSuffixes) {
		return true, false
	}
	return false, false
}

func isPatronymic(low string) bool {
	return len([]rune(low)) >= 5 && hasAnySuffix(low, patronymicSuffixes)
}

// disqualified — слово, которое не может быть частью имени (нарицательное,
// служебное, роль, топоним/юрлицо).
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

// findFIOMorph детектирует ФИО по морфологии слов, без опоры на регистр и
// слова-маркеры. Правило против ложных срабатываний: окно из 2–3 соседних слов
// маскируется, только если ВСЕ слова похожи на имя И среди них есть хотя бы один
// сильный якорь (словарное имя или отчество). Одиночное слово-фамилия («бензин»)
// никогда не срабатывает; одиночное отчество — срабатывает (высокая точность).
func (s *Service) findFIOMorph(input string, b2r []int) []types.Span {
	tokens := s.reWord.FindAllStringIndex(input, -1)
	var result []types.Span

	i := 0
	for i < len(tokens) {
		matched := false
		// Жадно пробуем окна от 3 слов к 1.
		for w := 3; w >= 1; w-- {
			if i+w > len(tokens) {
				continue
			}
			if !adjacentTokens(input, tokens, i, i+w-1) {
				continue
			}

			lows := make([]string, w)
			nameLike, strong := 0, 0
			for k := 0; k < w; k++ {
				t := tokens[i+k]
				lows[k] = strings.ToLower(input[t[0]:t[1]])
				nl, st := s.classifyName(lows[k])
				if nl {
					nameLike++
				}
				if st {
					strong++
				}
			}

			ok := false
			if w >= 2 {
				// Основное правило: все слова именоподобны и есть сильный якорь.
				ok = nameLike == w && strong >= 1
				// Мостик: «фамилия — [неизвестное имя] — отчество». Крайние слова
				// именоподобны, есть сильный якорь, а середина — не служебное слово.
				if !ok && w == 3 && strong >= 1 {
					nl0, _ := s.classifyName(lows[0])
					nl2, _ := s.classifyName(lows[2])
					if nl0 && nl2 && !s.disqualified(lows[1]) {
						ok = true
					}
				}
			} else {
				// Одиночное слово — только уверенное отчество.
				ok = isPatronymic(lows[0])
			}

			if ok && !s.morphIsFalse(lows) {
				result = append(result, runeSpan(b2r, tokens[i][0], tokens[i+w-1][1], "FIO"))
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

// adjacentTokens проверяет, что между словами [from..to] только пробелы/дефис —
// то есть это одно словосочетание, а не разные предложения.
func adjacentTokens(input string, tokens [][]int, from, to int) bool {
	for k := from; k < to; k++ {
		gap := input[tokens[k][1]:tokens[k+1][0]]
		if len(gap) == 0 || len(gap) > 3 {
			return false
		}
		for _, r := range gap {
			if r != ' ' && r != '\t' && r != '-' {
				return false
			}
		}
	}
	return true
}

// morphIsFalse отбрасывает топонимы/юрлица и публичных личностей.
func (s *Service) morphIsFalse(lows []string) bool {
	for _, l := range lows {
		if s.inSet(s.stopTokens, l) {
			return true
		}
	}
	if len(lows) >= 2 {
		if s.inSet(s.famousNames, strings.Join(lows, " ")) ||
			s.inSet(s.famousNames, lows[0]+" "+lows[1]) ||
			s.inSet(s.famousNames, lows[1]+" "+lows[0]) {
			return true
		}
	}
	return false
}

// findFIO детектирует капитализированное ФИО и форму инициалов. Ведущие ролевые
// слова («Клиент», «Поэт») срезаются, публичные личности и топонимы отбрасываются.
func (s *Service) findFIO(input string, b2r []int) []types.Span {
	var result []types.Span

	for _, m := range s.reFIO.FindAllStringSubmatchIndex(input, -1) {
		// Защита от точки в конце предыдущего предложения
		if m[0] > 0 && input[m[0]-1] == '.' {
			continue
		}

		var toks []fioToken
		for g := 1; g <= 4; g++ {
			a, b := m[2*g], m[2*g+1]
			if a >= 0 {
				toks = append(toks, fioToken{a, b, strings.ToLower(input[a:b])})
			}
		}

		// Срезаем ведущие ролевые слова — они не ПД
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

		result = append(result, runeSpan(b2r, core[0].start, core[len(core)-1].end, "FIO"))
	}

	for _, re := range []*regexp.Regexp{s.reFIOInitialsL, s.reFIOInitialsR} {
		for _, m := range re.FindAllStringIndex(input, -1) {
			result = append(result, runeSpan(b2r, m[0], m[1], "FIO"))
		}
	}

	return result
}

// coreIsFalse отсекает топонимы/юрлица (стоп-токены) и публичных личностей.
func (s *Service) coreIsFalse(core []fioToken) bool {
	lows := make([]string, len(core))
	for i, t := range core {
		if s.inSet(s.stopTokens, t.low) {
			return true
		}
		lows[i] = t.low
	}
	if s.inSet(s.famousNames, strings.Join(lows, " ")) {
		return true
	}
	if s.inSet(s.famousNames, lows[0]+" "+lows[1]) ||
		s.inSet(s.famousNames, lows[1]+" "+lows[0]) {
		return true
	}
	return false
}

func (s *Service) inSet(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

// findSpans возвращает спаны для матчей re. Если groups пуст — маскируется весь
// матч, иначе — только указанные группы захвата.
func (s *Service) findSpans(input string, b2r []int, re *regexp.Regexp, spanType string, groups ...int) []types.Span {
	var result []types.Span
	matches := re.FindAllStringSubmatchIndex(input, -1)

	for _, m := range matches {
		if len(groups) == 0 {
			result = append(result, runeSpan(b2r, m[0], m[1], spanType))
			continue
		}
		for _, g := range groups {
			if len(m) >= (g+1)*2 && m[g*2] >= 0 {
				result = append(result, runeSpan(b2r, m[g*2], m[g*2+1], spanType))
			}
		}
	}
	return result
}

// runeSpan переводит байтовые офсеты матча в рунные позиции за O(1) по карте b2r.
func runeSpan(b2r []int, sIdx, eIdx int, spanType string) types.Span {
	return types.Span{Start: b2r[sIdx], End: b2r[eIdx], Type: spanType}
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
