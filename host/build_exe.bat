@echo off
REM Builds PrivacySentinel.exe (no Python needed to run it afterwards).
cd /d "%~dp0"

python -m pip install --upgrade pyinstaller
if errorlevel 1 goto :fail

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name PrivacySentinel ^
  --icon app.ico ^
  --add-data "app.ico;." ^
  app_tk.py
if errorlevel 1 goto :fail

echo.
echo ================================================
echo  Built: %~dp0dist\PrivacySentinel.exe
echo ================================================
pause
exit /b 0

:fail
echo.
echo Build failed. Scroll up for the error message.
pause
exit /b 1
