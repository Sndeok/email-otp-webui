#!/bin/sh
set -eu

mkdir -p /app/config /app/data

if [ ! -f /app/config/config.json ]; then
  cp /app/config.example.json /app/config/config.json
  chmod 600 /app/config/config.json || true
  echo "[entrypoint] created default config: /app/config/config.json"
fi

chmod 600 /app/config/config.json 2>/dev/null || true
chmod 600 /app/config/webui.secret 2>/dev/null || true

python /app/email_otp_service.py \
  --config /app/config/config.json \
  --db /app/data/email_otp_service.sqlite3 \
  serve \
  --host 127.0.0.1 \
  --port 8088 &

SERVICE_PID="$!"

cleanup() {
  echo "[entrypoint] stopping services..."
  kill "$SERVICE_PID" 2>/dev/null || true
  wait "$SERVICE_PID" 2>/dev/null || true
}
trap cleanup TERM INT

# Give the local refresh service a short moment to bind before WebUI starts.
sleep 1

python /app/email_otp_webui.py \
  --host 0.0.0.0 \
  --port 8090 &

WEBUI_PID="$!"
wait "$WEBUI_PID"
cleanup
