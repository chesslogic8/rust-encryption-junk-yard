@echo off
setlocal enabledelayedexpansion

REM This batch file first checks the resolution of in.mp4.
REM If the height is less than 1080, it upscales to 1080p while preserving aspect ratio (letterboxing if needed).
REM Then processes to out.mp4 with high-quality settings for YouTube.
REM Uses H.264 with slow preset, CRF 18 for excellent quality, yuv420p pixel format.
REM Audio to AAC at 192k bitrate.
REM Also adds YouTube-recommended parameters: high profile, level 4.1 for better compatibility.

echo Starting script...

REM Check if in.mp4 exists
if not exist "in.mp4" (
    echo Error: in.mp4 not found in the current directory.
    pause
    exit /b
)

echo in.mp4 found.

REM Get video height using ffprobe
set "height="
for /f "delims=" %%a in ('ffprobe -v error -select_streams v:0 -show_entries stream^=height -of csv^=p^=0 "in.mp4" 2^>^&1') do set "height=%%a"

if not defined height (
    echo Error: Failed to get video height. Ensure ffprobe is installed and in PATH, and in.mp4 is a valid video.
    pause
    exit /b
)

echo Height: !height!

REM Default scale filter: no upscale
set "scale_filter= -pix_fmt yuv420p"

REM If height < 1080, upscale to 1080p preserving aspect ratio with letterbox
if !height! LSS 1080 (
    set "scale_filter= -vf "scale=-2:1080:flags=lanczos,format=yuv420p""
    echo Upscaling to 1080p.
) else (
    echo No upscale needed.
)

echo Running FFmpeg...

ffmpeg -i "in.mp4" -c:v libx264 -preset slow -crf 18 -profile:v high -level 4.1 !scale_filter! -c:a aac -b:a 192k "out.mp4"

if errorlevel 1 (
    echo Error: FFmpeg processing failed.
) else (
    echo Processing complete. Upload out.mp4 to YouTube.
)

pause