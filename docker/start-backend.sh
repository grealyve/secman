#!/bin/bash
set -e

echo "[start-backend.sh] Waiting for PostgreSQL..."
while ! pg_isready -h localhost -p 5432 -U postgres > /dev/null 2>&1; do
  sleep 2
done
echo "[start-backend.sh] PostgreSQL is ready. Starting app."

exec /app/main