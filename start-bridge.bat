@echo off
REM ============================================================
REM  Tatar Relay - start the local bridge (with key capture)
REM  Double-click to run, or:  start-bridge.bat examples\my.yaml
REM  or drag a .yaml file onto this .bat.
REM  For a personal, non-committed copy: copy this to
REM  start-bridge.local.bat and hard-code your profile (gitignored).
REM ============================================================

setlocal
cd /d "%~dp0"

REM --- default profile (edit or pass as an argument) ---
set "PROFILE=examples\acme-bank-mobile.yaml"
if not "%~1"=="" set "PROFILE=%~1"

echo(
echo   Tatar Relay bridge
echo   profile : %PROFILE%
echo   bridge  : http://127.0.0.1:8799
echo   capture : http://127.0.0.1:9091/key   (JS hook posts the session key here)
echo(
echo   Keep this window OPEN. Close it (or Ctrl+C) to stop the bridge.
echo   Next: load burp\build\libs\tatar-relay-burp.jar in Burp, inject the JS
echo         hook (examples\js-hooks\session_key_capture.js), then log in.
echo(

relay bridge "%PROFILE%" --capture

echo(
echo   Bridge stopped.
pause
endlocal
