ffmpeg -i "in.mp4" -c:v libx264 -preset medium -crf 15 ^
  -vf "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,format=yuv420p" ^
  -c:a aac -b:a 192k "out_1080p_PERFECT.mp4"

pause