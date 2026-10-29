@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  py -3 -m atlasac %*
) else (
  python -m atlasac %*
)
if %ERRORLEVEL% NEQ 0 pause
