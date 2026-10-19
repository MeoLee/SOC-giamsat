@echo off
setlocal
rem SOC-AI UI BRAND
chcp 65001 >nul
set "PYTHONUTF8=1"
title AI Dashboard
cd /d "%~dp0"
set "SOC_INFER_PY=%~dp0..\.venv-infer\Scripts\python.exe"
set "SOC_MODEL_DIR=E:\SOC-Lab\AI\runs\mlp-lab-20261014-212857"
if not "%~1"=="" set "SOC_MODEL_DIR=%~1"
if not exist "%SOC_INFER_PY%" (
  echo Inference environment not found: %SOC_INFER_PY%
  pause
  exit /b 1
)
"%SOC_INFER_PY%" -u lab_live.py --model "%SOC_MODEL_DIR%" --config live-config.json --output-dir "E:\SOC-Lab\AI\live" --publish-wazuh
set "SOC_EXIT_CODE=%ERRORLEVEL%"
echo.
echo AI watcher exit=%SOC_EXIT_CODE%
pause
exit /b %SOC_EXIT_CODE%
