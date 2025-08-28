#!/bin/bash
set -e

echo "[init-db.sh] Waiting for PostgreSQL..."
while ! pg_isready -h localhost -p 5432 -U postgres; do
  sleep 2
done
echo "[init-db.sh] PostgreSQL is ready."

if psql -h localhost -U postgres -lqt | cut -d \| -f 1 | grep -qw lutenix_db; then
    echo "[init-db.sh] Database already exists."
else
    echo "[init-db.sh] Creating database and user..."
    psql -h localhost -v ON_ERROR_STOP=1 --username "postgres" <<-EOSQL
        CREATE USER lutenix WITH SUPERUSER PASSWORD 'lutenix';
        CREATE DATABASE lutenix_db OWNER lutenix;
EOSQL
    echo "[init-db.sh] Database and user created."
fi

echo "[init-db.sh] Running SQL files..."
for sql_file in /app/database/init/*.sql; do
  if [ -f "$sql_file" ]; then
    echo "--> Running $sql_file"
    psql -h localhost -U lutenix -d lutenix_db -f "$sql_file"
  fi
done

echo "[init-db.sh] Initialization finished."