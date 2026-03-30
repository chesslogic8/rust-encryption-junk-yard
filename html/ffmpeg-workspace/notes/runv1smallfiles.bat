ffmpeg -i "in.mp4" -c:v copy -c:a aac -b:a 192k -vf "scale=1920:1080:force_original_aspect_ratio=decrease:preset=slow,format=yuv420p" -crf 18 -b:v 15M "out.mp4"

pause