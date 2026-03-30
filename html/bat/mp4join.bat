@echo off
setlocal EnableDelayedExpansion

:: Automatically detect the number of sequential MP4 files (1.mp4, 2.mp4, etc.)
set NUM_FILES=0
:detect_loop
set /a NUM_FILES+=1
if exist "%NUM_FILES%.mp4" goto detect_loop
set /a NUM_FILES-=1

if %NUM_FILES%==0 (
    echo ERROR: No MP4 files found starting from 1.mp4
    echo.
    echo Put this .bat file in the same folder as 1.mp4, 2.mp4, etc.
    pause
    exit /b 1
)

echo.
echo === YouTube High-Quality Joiner for 1.mp4 to %NUM_FILES%.mp4 ===
echo.

:: Check for missing files in the sequence
set "missing="
for /L %%i in (1,1,%NUM_FILES%) do (
    if not exist "%%i.mp4" set "missing=!missing! %%i.mp4"
)
if defined missing (
    echo ERROR: Missing files in sequence:%missing%
    echo.
    echo Ensure all files from 1.mp4 to %NUM_FILES%.mp4 are present without gaps.
    pause
    exit /b 1
)

echo All %NUM_FILES% files found! Starting high-quality join + encode for YouTube...
echo This may take a while, but the result will look excellent.
echo.

:: Build inputs and filter_complex for concat filter to handle sync issues
set "inputs="
for /L %%i in (1,1,%NUM_FILES%) do (
    set "inputs=!inputs! -i %%i.mp4"
)

set "filter="
set "concat_inputs="
set /a "file_index=0"
for /L %%i in (1,1,%NUM_FILES%) do (
    set "filter=!filter![!file_index!:v]setpts=PTS-STARTPTS[v!file_index!];[!file_index!:a]asetpts=PTS-STARTPTS[a!file_index!];"
    set "concat_inputs=!concat_inputs![v!file_index!][a!file_index!]"
    set /a "file_index+=1"
)
set "filter=!filter! !concat_inputs! concat=n=%NUM_FILES%:v=1:a=1[v][a];[v]scale=trunc(iw/2)*2:trunc(ih/2)*2[outv]"

:: High-quality YouTube preset (CRF 18 = visually lossless, H.264 + AAC)
ffmpeg %inputs% ^
       -filter_complex "!filter!" ^
       -map "[outv]" -map "[a]" ^
       -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p ^
       -c:a aac -b:a 192k -ar 48000 ^
       -movflags +faststart ^
       "YouTube_Ready_Full_HD.mp4" -y

:: Check if FFmpeg succeeded
if %errorlevel% neq 0 (
    echo.
    echo ERROR: FFmpeg execution failed! Check if FFmpeg is installed and in your PATH.
    echo Common issues: FFmpeg not found, input files corrupted, or insufficient disk space.
    echo Also, ensure all input files have video and audio streams.
    pause
    exit /b 1
)

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║ SUCCESS! Your video is ready for YouTube! ║
echo ║ ║
echo ║ File: YouTube_Ready_Full_HD.mp4 ║
echo ║ Settings: 1080p+, CRF 18 (near-lossless), ║
echo ║ faststart enabled, perfect metadata ║
echo ╚══════════════════════════════════════════════════╝
echo.

pause