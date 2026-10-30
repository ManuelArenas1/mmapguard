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

# Voz: formante de espeak-ng (es-419, variante +m3) con una cadena de
# post-procesado en ffmpeg para suavizar el timbre robotico (EQ calida,
# compresion suave, un toque de "room tone" y normalizacion de loudness).
# Nota: no hay una voz neuronal disponible en este entorno (el acceso de
# red a proveedores de modelos como huggingface.co esta bloqueado por la
# politica de red de la sesion); ver README para como mejorar esto si se
# habilita el acceso.
VOICE_FILTER="equalizer=f=200:t=q:w=1:g=3,equalizer=f=3200:t=q:w=1.2:g=-4,equalizer=f=7500:t=q:w=1:g=-5,acompressor=threshold=-18dB:ratio=3:attack=8:release=120:makeup=2,aecho=0.85:0.6:28:0.18,loudnorm=I=-17:TP=-1.5:LRA=9"

> concat.txt
while read -r id; do
  echo "== $id =="
  espeak-ng -v es-419+m3 -s 168 -p 40 -g 2 -f "audio/${id}.txt" -w "audio/${id}.wav" < /dev/null
  # small pad for breathing room, kept short to respect the 5-minute limit
  ffmpeg -nostdin -y -loglevel error -i "audio/${id}.wav" -af "adelay=250|250,apad=pad_dur=0.4,${VOICE_FILTER}" -ar 44100 "audio/${id}_pad.wav" < /dev/null
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
