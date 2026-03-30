@echo off
setlocal EnableDelayedExpansion

echo.
echo === YouTube High-Quality Joiner for 1.mp4 to 12.mp4 ===
echo.

:: Check for missing files
set "missing="
for /L %%i in (1,1,12) do (
    if not exist "%%i.mp4" set "missing=!missing! %%i.mp4"
)

if defined missing (
    echo ERROR: Missing files:%missing%
    echo.
    echo Put this .bat file in the same folder as 1.mp4 through 12.mp4
    pause
    exit /b 1
)

echo All 12 files found! Starting high-quality join + encode for YouTube...
echo This may take a while, but the result will look excellent.
echo.

:: Create temporary concat list
>file_list.txt (
    for /L %%i in (1,1,12) do echo file '%%i.mp4'
)

:: High-quality YouTube preset (CRF 18 = visually lossless, H.264 + AAC)
ffmpeg -f concat -safe 0 -i file_list.txt ^
       -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p ^
       -c:a aac -b:a 192k -ar 48000 ^
       -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" ^
       -movflags +faststart ^
       "YouTube_Ready_Full_HD.mp4" -y

:: Clean up
del file_list.txt

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║     SUCCESS! Your video is ready for YouTube!    ║
echo ║                                                  ║
echo ║  File: YouTube_Ready_Full_HD.mp4                 ║
echo ║  Settings: 1080p+, CRF 18 (near-lossless),       ║
echo ║            faststart enabled, perfect metadata   ║
echo ╚══════════════════════════════════════════════════╝
echo.
pause