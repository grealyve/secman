#!/bin/bash

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to start..."
until pg_isready -h localhost -p 5432 -U lutenix; do
  echo "PostgreSQL is not ready yet..."
  sleep 2
done

echo "PostgreSQL is ready. Initializing database..."

# Run SQL files in order
for sql_file in /app/database/init/*.sql; do
  if [ -f "$sql_file" ]; then
    echo "Executing $sql_file..."
    PGPASSWORD=lutenix psql -h localhost -U lutenix -d lutenix_db -f "$sql_file"
    if [ $? -eq 0 ]; then
      echo "Successfully executed $sql_file"
    else
      echo "Error executing $sql_file"
    fi
  fi
done

echo "Database initialization completed!" 