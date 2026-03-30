@echo off
setlocal enabledelayedexpansion

set count=1
for %%f in (*.mp3) do (
    ren "%%f" "!count!.mp3"
    set /a count+=1
)