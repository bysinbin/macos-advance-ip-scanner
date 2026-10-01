.PHONY: all build run cli app clean test

BINARY_NAME=macos-advance-ip-scanner

all: build

build:
	@echo "🔨 Derleniyor: $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) main.go
	@echo "✅ Derleme tamamlandı: ./$(BINARY_NAME)"

run: build
	@echo "🚀 Web arayüzü başlatılıyor..."
	./$(BINARY_NAME)

cli: build
	@echo "⚡ Terminal CLI taraması başlatılıyor..."
	./$(BINARY_NAME) --cli

app:
	@echo "📦 macOS .app paketi oluşturuluyor..."
	./scripts/build-app.sh

test:
	@echo "🧪 Testler çalıştırılıyor..."
	go test -v ./...

clean:
	@echo "🧹 Temizleniyor..."
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f scan-results.csv scan-results.json scan-results.txt
	@echo "✅ Temizlik tamamlandı."
