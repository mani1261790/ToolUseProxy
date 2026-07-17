@echo off
if "%~1"=="" (
  echo usage: run_cli.cmd ^<tooluseproxy arguments^> 1>&2
  exit /b 2
)
where py >nul 2>nul
if errorlevel 1 (
  echo tooluseproxy: Python 3.11 or newer is required 1>&2
  exit /b 1
)
py -3.11 "%~dp0..\tooluseproxy_plugin.py" %*
exit /b %errorlevel%
