@echo off
chcp 65001 >nul
if "%~1"=="" (
  echo 使い方: run_cli.cmd ^<ToolUseProxyの引数^> 1>&2
  exit /b 2
)
set "TOOLUSEPROXY_CODEX_PLUGIN_ROOT=%~dp0.."
where py >nul 2>nul
if errorlevel 1 (
  echo ToolUseProxyの実行にはPython 3.11または3.12が必要です。 1>&2
  exit /b 1
)
py -3.12 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python312
py -3.11 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python311
echo ToolUseProxyの実行にはPython 3.11または3.12が必要です。 1>&2
exit /b 1

:run_python312
py -3.12 "%~dp0..\tooluseproxy_plugin.py" %*
exit /b %errorlevel%

:run_python311
py -3.11 "%~dp0..\tooluseproxy_plugin.py" %*
exit /b %errorlevel%
