#!/bin/zsh
set -eu
SCENE_DIR=${0:A:h}
ENGINE_DIR='/Users/Shared/Epic Games/UE_5.8'
exec "$ENGINE_DIR/Engine/Binaries/Mac/UnrealEditor-Cmd" "$SCENE_DIR/Nocturne.uproject" \
  -run=pythonscript -script="$SCENE_DIR/render_scene.py" \
  -unattended -AllowCommandletRendering -RenderOffscreen -nosound -nop4 -ddc=NoShared \
  -stdout -abslog="$SCENE_DIR/render.log"
