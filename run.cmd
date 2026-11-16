@echo off
rem HybridSec launcher that works even when PowerShell's execution policy blocks scripts
rem (the default on a fresh Windows installation). It runs run.ps1 with the policy bypassed
rem for this one process only; nothing on the machine is changed.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
if errorlevel 1 pause
