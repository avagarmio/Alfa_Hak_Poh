// Нагрузочный генератор: N воркеров в течение duration шлют пары
// маскирование+демаскирование с уникальным payload_id и считают RPS/latency.
// Запуск:  go run ./cmd/loadtest -url http://localhost:8080/process -c 200 -d 30s
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8080/process", "эндпоинт /process")
	conc := flag.Int("c", 200, "число конкурентных воркеров")
	dur := flag.Duration("d", 30*time.Second, "длительность теста")
	flag.Parse()

	const payload = "Клиент Иванов Иван Иванович, паспорт 4509 123456, " +
		"тел +7 999 123-45-67, карта 4539 1488 0343 6467, почта a@b.ru"

	var total, ok, errc, mismatch, latSum int64
	deadline := time.Now().Add(*dur)
	client := &http.Client{Timeout: 10 * time.Second}

	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; time.Now().Before(deadline); i++ {
				pid := fmt.Sprintf("lt-%d-%d", id, i)
				start := time.Now()
				masked, err := do(client, *url, payload, pid)
				var back string
				if err == nil {
					back, err = do(client, *url, masked, pid) // демаск может уйти на др. инстанс
				}
				atomic.AddInt64(&total, 1)
				atomic.AddInt64(&latSum, time.Since(start).Nanoseconds())
				switch {
				case err != nil:
					atomic.AddInt64(&errc, 1)
				case back != payload:
					atomic.AddInt64(&mismatch, 1)
				default:
					atomic.AddInt64(&ok, 1)
				}
			}
		}(w)
	}
	wg.Wait()

	secs := (*dur).Seconds()
	fmt.Printf("Пар (маска+демаска): %d\n", total)
	fmt.Printf("Успешных round-trip:  %d\n", ok)
	fmt.Printf("Ошибок:               %d\n", errc)
	fmt.Printf("Несовпадений демаска:  %d\n", mismatch)
	fmt.Printf("RPS (HTTP-запросов):  %.0f\n", float64(total)*2/secs)
	if total > 0 {
		fmt.Printf("Средняя latency пары:  %.2f ms\n", float64(latSum)/float64(total)/1e6)
	}
}

func do(c *http.Client, url, payload, pid string) (string, error) {
	body, _ := json.Marshal(map[string]string{"payload": payload, "payload_id": pid})
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var r struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.Result, nil
}
