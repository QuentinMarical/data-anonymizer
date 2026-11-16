@echo off
rem Active ou désactive le garde data-anonymizer.
rem Usage : glisser le dossier du projet sur ce fichier, ou le lancer depuis le dossier du projet.
setlocal
chcp 65001 >nul
set "PROJECT=%~1"
if "%PROJECT%"=="" set "PROJECT=%CD%"
python "%~dp0..\scripts\toggle.py" --project "%PROJECT%" toggle
echo.
pause
