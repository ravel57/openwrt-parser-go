#!/usr/bin/env bash

set -Eeuo pipefail

original_dir="$(pwd)"
frontend_dir="$original_dir/../../WebstormProjects/mikrotik_parser"
destination="$original_dir/web/dist"

cleanup() {
  cd "$original_dir"
}
trap cleanup EXIT

if [[ ! -d "$frontend_dir" ]]; then
  echo "Error: frontend directory not found: $frontend_dir" >&2
  exit 1
fi

cd "$frontend_dir"

npm install
npm run build

if [[ ! -d "./dist" ]]; then
  echo "Copying error: ./dist not found" >&2
  exit 1
fi

rm -rf "$destination"
mkdir -p "$destination"
cp -a ./dist/. "$destination/"

echo "Frontend build copied to: $destination"
