@echo off
title XONI-WEB 2026 - Analizador de URLs
color 0A

:: ============================================================
:: SOLICITAR PERMISOS DE ADMINISTRADOR
:: ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de administrador...
    echo.
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

:: ============================================================
:: EJECUTAR start.py CON PERMISOS DE ADMINISTRADOR
:: ============================================================
cls
echo ============================================================
echo              XONI-WEB 2026 - Analizador de URLs
echo              Web Scraping + VirusTotal API
echo              (Modo Administrador)
echo ============================================================
echo.
echo [OK] Permisos de administrador obtenidos
echo.
echo Iniciando XONI-WEB...
echo.
echo [INFO] Asegurate de tener tu API Key de VirusTotal
echo [INFO] Si no la tienes, el programa te la pedira
echo [INFO] Puedes obtenerla en: virustotal.com
echo.
echo Presiona Ctrl+C para detener
echo ============================================================
echo.

python start.py

pause
