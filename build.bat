@echo off
rem Сборка SS_Checker.exe (один файл, сразу запрашивает права администратора).
rem Нужен Python 3.8+ для Windows: https://www.python.org/downloads/windows/
chcp 65001 >nul
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || goto :err
python -m unittest discover -s tests || goto :err
python -m PyInstaller --noconfirm --clean --onefile --console --uac-admin ^
    --name SS_Checker ss_checker.py || goto :err
echo.
echo Готово: dist\SS_Checker.exe
pause
exit /b 0
:err
echo Сборка не удалась.
pause
exit /b 1
