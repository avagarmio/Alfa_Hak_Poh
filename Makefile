APP := llm-proxy
BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: build run test vet tidy bench frontend-install frontend-run frontend-build package

build:
	cd $(BACKEND_DIR) && mkdir -p bin && go build -o bin/$(APP) ./cmd

run:
	cd $(BACKEND_DIR) && go run ./cmd

test:
	cd $(BACKEND_DIR) && go test ./...

vet:
	cd $(BACKEND_DIR) && go vet ./...

tidy:
	cd $(BACKEND_DIR) && go mod tidy

bench:
	cd $(BACKEND_DIR) && go test ./internal/service/ -bench=. -benchmem -run=^$$

frontend-install:
	cd $(FRONTEND_DIR) && npm install

frontend-run:
	cd $(FRONTEND_DIR) && npm run dev

frontend-build:
	cd $(FRONTEND_DIR) && npm run build

package:
	rm -f solution.zip
	zip -r solution.zip . \
	  -x '*.git*' \
	     'backend/bin/*' \
	     'frontend/node_modules/*' \
	     'frontend/dist/*' \
	     'for_agent/*' \
	     '*.zip' \
	     'review.md' \
	     '*.idea*' \
	     '*.vscode*' \
	     '*/tmp/*'
