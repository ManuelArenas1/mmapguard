#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
mkdir -p audio clips

python3 - << 'PYEOF'
import json
with open("scenes.json") as f:
    scenes = json.load(f)
with open("ids.txt", "w") as f:
    for s in scenes:
        f.write(s["id"] + "\n")
    for s in scenes:
        with open(f"audio/{s['id']}.txt", "w") as nf:
            nf.write(s["narration"])
PYEOF

> concat.txt
while read -r id; do
  echo "== $id =="
  espeak-ng -v es-419 -s 168 -p 45 -g 3 -f "audio/${id}.txt" -w "audio/${id}.wav" < /dev/null
  # small pad for breathing room, kept short to respect the 5-minute limit
  ffmpeg -nostdin -y -loglevel error -i "audio/${id}.wav" -af "adelay=250|250,apad=pad_dur=0.4" "audio/${id}_pad.wav" < /dev/null
  dur=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "audio/${id}_pad.wav" < /dev/null)
  echo "$id duration=$dur"
  ffmpeg -nostdin -y -loglevel error -loop 1 -i "slides/${id}.png" -i "audio/${id}_pad.wav" \
    -c:v libx264 -preset veryfast -tune stillimage -pix_fmt yuv420p \
    -c:a aac -b:a 160k -shortest -t "$dur" -r 30 \
    "clips/${id}.mp4" < /dev/null
  echo "file 'clips/${id}.mp4'" >> concat.txt
done < ids.txt

ffmpeg -nostdin -y -loglevel error -f concat -safe 0 -i concat.txt -c copy mmapguard_demo.mp4 < /dev/null
ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 mmapguard_demo.mp4
