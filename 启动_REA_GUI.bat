@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0rea_gui.py"
) else (
    python "%~dp0rea_gui.py"
)
if errorlevel 1 pause