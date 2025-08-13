@echo off
echo Starting Git push process...

REM Configure Git
git config --global user.email "phishingcatcher@example.com"
git config --global user.name "PhishingCatcher"

REM Initialize repository if needed
if not exist .git (
    echo Initializing Git repository...
    git init
)

REM Add all files
echo Adding files to Git...
git add -A

REM Commit changes
echo Committing changes...
git commit -m "Complete English translation and enterprise features - Professional phishing analysis tool"

REM Set up remote if not exists
git remote remove origin 2>nul
git remote add origin https://github.com/your-username/PhishingCatcher.git

REM Set main branch
git branch -M main

REM Push to repository
echo Pushing to repository...
git push -u origin main --force

echo Push completed!
pause
