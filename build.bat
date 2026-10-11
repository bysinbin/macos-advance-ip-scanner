@echo off
chcp 65001 > nul
echo ========================================================
echo   Advanced IP Scanner - Windows Derleyici
echo ========================================================
echo.
echo [1/2] Go derlemesi baslatiliyor...
go build -ldflags="-s -w" -o ip-scanner.exe main.go
if %ERRORLEVEL% NEQ 0 (
    echo [HATA] Derleme basarisiz oldu!
    pause
    exit /b %ERRORLEVEL%
)

echo [2/2] Derleme tamamlandi: ip-scanner.exe
echo.
echo Baslatmak icin:
echo   - Web Arayuzu: ip-scanner.exe (veya run.bat)
echo   - CLI Modu:   ip-scanner.exe --cli
echo.
pause
