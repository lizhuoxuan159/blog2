@echo off
chcp 65001
git pull --rebase
git status --porcelain > temp.txt
for %%i in (temp.txt) do if %%~zi gtr 0 (
git add .
git commit -m "auto sync by bat"
git push origin
)
del temp.txt
pause
