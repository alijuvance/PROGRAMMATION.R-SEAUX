@echo off
echo ===================================================
echo     LANCEMENT IDS RESEAU (Dashboard + Detecteur)
echo ===================================================

:: Demander les droits administrateur pour l'IDS
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Privileges administrateur detectes.
) else (
    echo [!] ERREUR : Ce script doit etre lance en tant qu'Administrateur !
    echo     Faites un clic droit sur start.bat ^> Executer en tant qu'administrateur
    pause
    exit /b 1
)

:: Verifier que Python est installe
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Python n'est pas installe ou n'est pas dans le PATH.
    pause
    exit /b 1
)

:: Installer les dependances silencieusement
echo [*] Verification des dependances...
pip install -r requirements.txt -q

:: Lancer le Dashboard dans une nouvelle fenetre
echo [*] Lancement du Dashboard (Port 5000)...
start "IDS Dashboard" cmd /c "python dashboard/app.py"

:: Lancer l'IDS dans la fenetre actuelle
echo [*] Lancement de l'IDS (Moteur de detection)...
echo.
python src/ids_detecteur.py

pause
