@echo off
chcp 65001 > nul
if not exist "ip-scanner.exe" (
    echo ip-scanner.exe bulunamadi, derleniyor...
    go build -ldflags="-s -w" -o ip-scanner.exe main.go
    if %ERRORLEVEL% NEQ 0 (
        echo [HATA] Derleme basarisiz oldu!
        pause
        exit /b %ERRORLEVEL%
    )
)
echo Advanced IP Scanner baslatiliyor...
start "" "ip-scanner.exe"
