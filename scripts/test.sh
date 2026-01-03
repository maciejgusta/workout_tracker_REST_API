#!/usr/bin/env bash
set -euo pipefail

compose=(docker compose -f docker-compose.test.yml)

"${compose[@]}" up --build -d --remove-orphans
trap '"${compose[@]}" down -v' EXIT

"${compose[@]}" logs -f --no-color api_test

exit_code=$("${compose[@]}" wait api_test)
if [ "$exit_code" -ne 0 ]; then
  echo "api_test failed; db_test logs:" >&2
  "${compose[@]}" logs --no-color --tail=200 db_test
  exit "$exit_code"
fi
