@echo off
rem ===== Srun auto-login launcher =====
rem   Usage: 启动.bat [args for srun_portal.py] [nopause]
rem   "nopause" = do not wait for a key press (used by the watchdog script)
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Srun Auto Login

set "NOPAUSE="
for %%A in (%*) do if /i "%%A"=="nopause" set "NOPAUSE=1"

set "PYEXE="
for %%P in (python.exe) do if not defined PYEXE set "PYEXE=%%~$PATH:P"
if not defined PYEXE if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYEXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYEXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PYEXE if exist "C:\Python312\python.exe" set "PYEXE=C:\Python312\python.exe"
if not defined PYEXE if exist "%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe" set "PYEXE=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"

if not defined PYEXE (
  echo [ERROR] Python not found on this computer.
  echo         Install Python 3 from https://www.python.org/downloads/
  echo         ^(remember to tick "Add python.exe to PATH"^)
  if not defined NOPAUSE pause
  exit /b 1
)

set "PYTHONIOENCODING=utf-8"
echo [%DATE% %TIME%] using: %PYEXE%
"%PYEXE%" "%~dp0srun_portal.py" %*
set "RC=%ERRORLEVEL%"
echo [%DATE% %TIME%] srun_portal.py exited with code %RC%
if not defined NOPAUSE pause
exit /b %RC%
