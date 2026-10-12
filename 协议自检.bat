@echo off
rem ===== Offline protocol self-test: rebuilds the captured login request byte by byte =====
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "PYEXE="
for %%P in (python.exe) do if not defined PYEXE set "PYEXE=%%~$PATH:P"
if not defined PYEXE if exist "%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe" set "PYEXE=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
if not defined PYEXE ( echo [ERROR] Python not found. & pause & exit /b 1 )
set "PYTHONIOENCODING=utf-8"
"%PYEXE%" "%~dp0srun_portal.py" --selftest
if errorlevel 1 ( echo. & echo [FAILED] protocol self-test failed )
pause
