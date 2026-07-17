@echo off
if "%~1"=="" exit /b 0
if "%PLUGIN_ROOT%"=="" exit /b 0
if "%PLUGIN_DATA%"=="" exit /b 0
where py >nul 2>nul
if errorlevel 1 (
  echo ToolUseProxy inactive ^(python_missing^): Python 3.11 or newer is required 1>&2
  exit /b 0
)
py -3.11 "%PLUGIN_ROOT%\tooluseproxy_plugin.py" hook "%~1" --data-dir "%PLUGIN_DATA%"
if errorlevel 1 exit /b 0
exit /b 0
