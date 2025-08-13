@echo off
echo ========================================
echo    PhishingCatcher - Demarrage
echo ========================================
echo.

REM Vérifier si Python est installé
echo [INFO] Verification de Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installé ou n'est pas dans le PATH
    echo Veuillez installer Python 3.12+ depuis https://python.org
    pause
    exit /b 1
)

echo [OK] Python detecte
python --version

REM Installer les dépendances si nécessaire
echo.
echo [INFO] Installation/verification des dependances...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERREUR] Echec de l'installation des dependances
    echo Verifiez votre connexion internet et reessayez
    pause
    exit /b 1
)

echo [OK] Dependances pretes

REM Vérifier Ollama rapidement
echo.
echo [INFO] Verification d'Ollama...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [ATTENTION] Ollama non detecte - L'analyse IA ne fonctionnera pas
    echo Installez Ollama depuis https://ollama.ai puis: ollama pull phi3
) else (
    echo [OK] Ollama detecte
)

REM Vérifier Docker rapidement
echo.
echo [INFO] Verification de Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ATTENTION] Docker non detecte - La sandbox ne fonctionnera pas
    echo Installez Docker Desktop depuis https://docker.com
) else (
    echo [OK] Docker detecte
)

echo.
echo ========================================
echo    Demarrage de PhishingCatcher
echo ========================================
echo.
echo L'application sera accessible sur: http://localhost:8501
echo Appuyez sur Ctrl+C pour arreter l'application
echo.

REM Démarrer l'application
streamlit run app.py

pause
