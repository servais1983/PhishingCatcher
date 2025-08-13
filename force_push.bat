@echo off
echo ========================================
echo FORCE PUSH PHISHINGCATCHER PROJECT
echo ========================================

echo.
echo 1. Configuring Git...
git config --global user.email "phishingcatcher@example.com"
git config --global user.name "PhishingCatcher"

echo.
echo 2. Initializing repository...
if not exist .git (
    git init
    echo Repository initialized.
) else (
    echo Repository already exists.
)

echo.
echo 3. Adding all files...
git add -A
echo Files added.

echo.
echo 4. Committing changes...
git commit -m "Complete English translation and enterprise features - Professional phishing analysis tool v1.0"
echo Commit completed.

echo.
echo 5. Setting up remote...
git remote remove origin 2>nul
git remote add origin https://github.com/your-username/PhishingCatcher.git
echo Remote configured.

echo.
echo 6. Setting main branch...
git branch -M main
echo Branch set to main.

echo.
echo 7. FORCE PUSHING TO REPOSITORY...
git push -u origin main --force
echo.
echo ========================================
echo PUSH COMPLETED!
echo ========================================
echo.
echo If you see any errors above, please:
echo 1. Check your GitHub repository URL
echo 2. Ensure you have write permissions
echo 3. Try running this script again
echo.
pause
