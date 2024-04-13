#!/bin/bash

main=$(docker-compose  version  --short | cut -d '.' -f 1)
minor=$(docker-compose  version  --short | cut -d '.' -f 2)
current=$(docker-compose  version  --short)

echo 'Checking docker compose version'
echo 'Supported docker compose version'
