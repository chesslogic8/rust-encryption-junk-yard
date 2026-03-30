@echo off
setlocal enabledelayedexpansion

:: Edit this variable to set the number of MP3 files to join (e.g., 1.mp3 to 5.mp3)
set NUM_FILES=29

:: Build the concat string
set "INPUTS=concat:"
for /L %%i in (1,1,%NUM_FILES%) do (
    set "INPUTS=!INPUTS!%%i.mp3|"
)

:: Remove the trailing pipe
set "INPUTS=!INPUTS:~0,-1!"

:: Run FFmpeg to join the files (assumes FFmpeg is in PATH and files are compatible)
ffmpeg -i "!INPUTS!" -c copy output.mp3

:: If files aren't compatible, use this instead (uncomment and comment the above):
:: ffmpeg -i "!INPUTS!" -acodec libmp3lame output.mp3

echo Done! Output saved as output.mp3