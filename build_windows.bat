@echo off
REM Build the Windows one-file executable: dist\DomainHunter.exe (run this on Windows)
cd /d "%~dp0"
py -3 -m venv .venv || exit /b 1
call .venv\Scripts\activate.bat || exit /b 1
pip install -q -r requirements.txt || exit /b 1
pyinstaller --noconfirm --clean --onefile --windowed --name DomainHunter main.py || exit /b 1
echo Built: %cd%\dist\DomainHunter.exe
