@echo off
chcp 65001
cd /d "D:\新建文件夹\新建文件夹\blog2"

::第一步：检测当前文件改动，输出到临时文件
git status --porcelain > temp.txt

::判断是否存在改动
for %%i in (temp.txt) do (
    if %%~zi gtr 0 (
        ::本地有修改：先add，再pull‑rebase，之后提交推送
        git add .
        git pull --rebase
        git commit -m "auto sync by bat"
        git push origin
    ) else (
        ::本地无改动，只拉取远程代码
        git pull --rebase
    )
)

::删除临时文件，避免被Git追踪
del temp.txt
pause
