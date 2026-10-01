#!/usr/bin/env bash
set -e

APP_NAME="Advanced IP Scanner"
BUNDLE_DIR="dist/${APP_NAME}.app"
CONTENTS_DIR="${BUNDLE_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

echo "🔨 Derleme başlatılıyor: ${APP_NAME}..."

# Build Go binary
mkdir -p "${MACOS_DIR}" "${RESOURCES_DIR}"
go build -ldflags="-s -w" -o "${MACOS_DIR}/macos-advance-ip-scanner" main.go

# Copy Info.plist
cp scripts/Info.plist "${CONTENTS_DIR}/Info.plist"

# Generate simple ICNS / icon placeholder if needed
chmod +x "${MACOS_DIR}/macos-advance-ip-scanner"

echo "✅ Başarıyla oluşturuldu: ${BUNDLE_DIR}"
echo "💡 Çalıştırmak için: open \"${BUNDLE_DIR}\""
