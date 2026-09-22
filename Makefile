APP := llm-proxy

.PHONY: build run test vet tidy bench package

build:
	go build -o bin/$(APP) ./cmd

run:
	go run ./cmd

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

bench:
	go test ./internal/service/ -bench=. -benchmem -run=^$$

# Упаковка решения по правилам ТЗ (раздел 7.1): только исходники и конфиги,
# без бинарников, .git, датасетов и служебных каталогов.
package:
	rm -f solution.zip
	zip -r solution.zip . \
	  -x '*.git*' 'bin/*' 'for_agent/*' '*.zip' 'review.md' \
	     '*.idea*' '*.vscode*' '*/tmp/*'
