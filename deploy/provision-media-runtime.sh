#!/usr/bin/env sh
# Provision ffmpeg and an optional checksum-pinned NSFW ONNX model for Aegis.
# Writes per-user config under ${XDG_CONFIG_HOME:-$HOME/.config}/aegis.

set -eu

INSTALL_FFMPEG=0
FFMPEG_PATH=""
MODEL_URL=""
MODEL_SHA256=""
CONFIG_DIR="${XDG_CONFIG_HOME:-"$HOME/.config"}/aegis"
MODEL_PATH="$CONFIG_DIR/models/nsfw.onnx"

while [ $# -gt 0 ]; do
  case "$1" in
    --install-ffmpeg) INSTALL_FFMPEG=1 ;;
    --ffmpeg-path) shift; FFMPEG_PATH="${1:-}" ;;
    --model-url) shift; MODEL_URL="${1:-}" ;;
    --model-sha256) shift; MODEL_SHA256="${1:-}" ;;
    --model-path) shift; MODEL_PATH="${1:-}" ;;
    --config-dir) shift; CONFIG_DIR="${1:-}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$CONFIG_DIR"

have() { command -v "$1" >/dev/null 2>&1; }

install_ffmpeg() {
  if have ffmpeg; then return 0; fi
  if [ "$INSTALL_FFMPEG" -ne 1 ]; then return 0; fi
  if have apt-get; then
    sudo apt-get update
    sudo apt-get install -y ffmpeg
  elif have dnf; then
    sudo dnf install -y ffmpeg
  elif have yum; then
    sudo yum install -y ffmpeg
  elif have brew; then
    brew install ffmpeg
  else
    echo "ffmpeg not found and no supported package manager detected" >&2
    exit 1
  fi
}

resolve_ffmpeg() {
  if [ -n "$FFMPEG_PATH" ]; then
    [ -x "$FFMPEG_PATH" ] || { echo "ffmpeg path is not executable: $FFMPEG_PATH" >&2; exit 1; }
    printf '%s\n' "$FFMPEG_PATH"
    return 0
  fi
  if have ffmpeg; then
    command -v ffmpeg
    return 0
  fi
  return 1
}

download() {
  url="$1"
  out="$2"
  mkdir -p "$(dirname "$out")"
  if have curl; then
    curl -fL "$url" -o "$out"
  elif have wget; then
    wget -O "$out" "$url"
  else
    echo "curl or wget is required to download a model" >&2
    exit 1
  fi
}

sha256_file() {
  if have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

install_ffmpeg

if FFMPEG_RESOLVED="$(resolve_ffmpeg 2>/dev/null)"; then
  printf '%s' "$FFMPEG_RESOLVED" > "$CONFIG_DIR/ffmpeg_binary.txt"
  echo "ffmpeg: $FFMPEG_RESOLVED"
else
  echo "ffmpeg not found; video analysis will fail open until ffmpeg is installed or FFMPEG_BINARY is set" >&2
fi

if [ -n "$MODEL_URL" ]; then
  if [ -z "$MODEL_SHA256" ]; then
    echo "--model-url requires --model-sha256 for checksum pinning" >&2
    exit 1
  fi
  download "$MODEL_URL" "$MODEL_PATH"
fi

if [ -f "$MODEL_PATH" ]; then
  if [ -n "$MODEL_SHA256" ]; then
    ACTUAL="$(sha256_file "$MODEL_PATH" | tr '[:upper:]' '[:lower:]')"
    EXPECTED="$(printf '%s' "$MODEL_SHA256" | tr '[:upper:]' '[:lower:]')"
    if [ "$ACTUAL" != "$EXPECTED" ]; then
      echo "model SHA-256 mismatch: expected $EXPECTED got $ACTUAL" >&2
      exit 1
    fi
  fi
  printf '%s' "$MODEL_PATH" > "$CONFIG_DIR/nsfw_model.txt"
  echo "NSFW model: $MODEL_PATH"
else
  echo "NSFW model not configured; ONNX image/video scoring will fail open until a model is provisioned" >&2
fi

cat > "$CONFIG_DIR/media-env.sh" <<EOF
export FFMPEG_BINARY="$(cat "$CONFIG_DIR/ffmpeg_binary.txt" 2>/dev/null || true)"
export AEGIS_FFMPEG_BINARY="\$FFMPEG_BINARY"
export AEGIS_NSFW_MODEL="$(cat "$CONFIG_DIR/nsfw_model.txt" 2>/dev/null || true)"
EOF

echo "env file: $CONFIG_DIR/media-env.sh"
