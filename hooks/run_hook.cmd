@echo off
chcp 65001 >nul
set "phase=%~1"
if "%phase%"=="" exit /b 0
if "%PLUGIN_ROOT%"=="" (
  call :emit_inactive plugin_environment "PLUGIN_ROOT and PLUGIN_DATA are required"
  exit /b 0
)
if "%PLUGIN_DATA%"=="" (
  call :emit_inactive plugin_environment "PLUGIN_ROOT and PLUGIN_DATA are required"
  exit /b 0
)
where py >nul 2>nul
if errorlevel 1 (
  call :emit_inactive python_missing "Python 3.11 or 3.12 is required"
  exit /b 0
)
py -3.12 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python312
py -3.11 -c "import sys" >nul 2>nul
if not errorlevel 1 goto run_python311
call :emit_inactive python_missing "Python 3.11 or 3.12 is required"
exit /b 0

:run_python312
set "hook_output=%TEMP%\tooluseproxy-hook-%RANDOM%-%RANDOM%.tmp"
py -3.12 "%PLUGIN_ROOT%\tooluseproxy_plugin.py" hook "%phase%" --data-dir "%PLUGIN_DATA%" >"%hook_output%" 2>nul
if errorlevel 1 goto runtime_start_failed
type "%hook_output%"
del /q "%hook_output%" >nul 2>nul
exit /b 0

:run_python311
set "hook_output=%TEMP%\tooluseproxy-hook-%RANDOM%-%RANDOM%.tmp"
py -3.11 "%PLUGIN_ROOT%\tooluseproxy_plugin.py" hook "%phase%" --data-dir "%PLUGIN_DATA%" >"%hook_output%" 2>nul
if errorlevel 1 goto runtime_start_failed
type "%hook_output%"
del /q "%hook_output%" >nul 2>nul
exit /b 0

:runtime_start_failed
del /q "%hook_output%" >nul 2>nul
call :emit_inactive runtime_start_failed "the local Hook runtime could not start"
exit /b 0

:emit_inactive
set "inactive_code=%~1"
set "inactive_message=ToolUseProxyを開始できなかったため、保護機能は動作していません。"
if /i "%inactive_code%"=="plugin_environment" set "inactive_message=ToolUseProxy Pluginの設定を読み込めないため、保護機能は動作していません。"
if /i "%inactive_code%"=="python_missing" set "inactive_message=Python 3.11または3.12が見つからないため、ToolUseProxyの保護機能は動作していません。"
if /i "%phase%"=="pre-tool-use" goto emit_pre
if /i "%phase%"=="post-tool-use" goto emit_post
if /i "%phase%"=="stop" goto emit_stop
echo %inactive_message%（技術情報: %inactive_code%） 1>&2
exit /b 0

:emit_pre
echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"%inactive_message%（技術情報: %inactive_code%）"}}
exit /b 0

:emit_post
echo {"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"%inactive_message%（技術情報: %inactive_code%）"}}
exit /b 0

:emit_stop
echo {"systemMessage":"%inactive_message%（技術情報: %inactive_code%）"}
exit /b 0
