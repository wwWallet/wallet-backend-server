#!/usr/bin/env sh
set -e

CONTAINER_NAME="wallet-backend-server"

echo "Running migrations inside container $CONTAINER_NAME..."
docker exec -it $CONTAINER_NAME yarn typeorm migration:run
echo "Migrations completed."
