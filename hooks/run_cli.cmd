@echo off
if "%~1"=="" (
  echo usage: run_cli.cmd ^<tooluseproxy arguments^> 1>&2
  exit /b 2
)
where py >nul 2>nul
if errorlevel 1 (
  echo tooluseproxy: Python 3.11 or 3.12 is required 1>&2
  exit /b 1
)
py -3.12 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python312
py -3.11 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python311
echo tooluseproxy: Python 3.11 or 3.12 is required 1>&2
exit /b 1

:run_python312
py -3.12 "%~dp0..\tooluseproxy_plugin.py" %*
exit /b %errorlevel%

:run_python311
py -3.11 "%~dp0..\tooluseproxy_plugin.py" %*
exit /b %errorlevel%
