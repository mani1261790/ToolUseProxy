@echo off
if "%~1"=="" exit /b 0
if "%PLUGIN_ROOT%"=="" exit /b 0
if "%PLUGIN_DATA%"=="" exit /b 0
where py >nul 2>nul
if errorlevel 1 (
  echo ToolUseProxy inactive ^(python_missing^): Python 3.11 or 3.12 is required 1>&2
  exit /b 0
)
py -3.12 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python312
py -3.11 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python311
echo ToolUseProxy inactive ^(python_missing^): Python 3.11 or 3.12 is required 1>&2
exit /b 0

:run_python312
py -3.12 "%PLUGIN_ROOT%\tooluseproxy_plugin.py" hook "%~1" --data-dir "%PLUGIN_DATA%"
exit /b 0

:run_python311
py -3.11 "%PLUGIN_ROOT%\tooluseproxy_plugin.py" hook "%~1" --data-dir "%PLUGIN_DATA%"
exit /b 0
