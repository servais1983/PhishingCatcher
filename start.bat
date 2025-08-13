@echo off
echo ========================================
echo    PhishingCatcher - Demarrage
echo ========================================
echo.

REM Vérifier si Python est installé
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installé ou n'est pas dans le PATH
    echo Veuillez installer Python 3.12+ depuis https://python.org
    pause
    exit /b 1
)

echo [OK] Python detecte
python --version

REM Vérifier si les dépendances sont installées
echo.
echo [INFO] Verification des dependances...
pip show streamlit >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installation des dependances...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERREUR] Echec de l'installation des dependances
        pause
        exit /b 1
    )
)

echo [OK] Dependances verifiees

REM Vérifier si Ollama est installé
echo.
echo [INFO] Verification d'Ollama...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [ATTENTION] Ollama n'est pas detecte
    echo L'analyse IA ne fonctionnera pas sans Ollama
    echo Installez Ollama depuis https://ollama.ai
    echo Puis executez: ollama pull phi3
    echo.
    set /p continue="Continuer sans IA? (o/n): "
    if /i not "%continue%"=="o" (
        echo Demarrage annule
        pause
        exit /b 1
    )
) else (
    echo [OK] Ollama detecte
    ollama --version
)

REM Vérifier si Docker est installé (optionnel)
echo.
echo [INFO] Verification de Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ATTENTION] Docker n'est pas detecte
    echo L'analyse dynamique (sandbox) ne fonctionnera pas
    echo Installez Docker Desktop pour cette fonctionnalite
) else (
    echo [OK] Docker detecte
    docker --version
)

echo.
echo ========================================
echo    Demarrage de PhishingCatcher
echo ========================================
echo.
echo L'application sera accessible sur: http://localhost:8501
echo.
echo Appuyez sur Ctrl+C pour arreter l'application
echo.

REM Démarrer l'application
streamlit run app.py

pause
