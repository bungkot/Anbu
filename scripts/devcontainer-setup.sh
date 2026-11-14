#!/usr/bin/env bash
# Dev container setup: install dependencies and ensure the pinned Ollama model
# (granite3.3:2b) is available. Runs inside the app container.
set -euo pipefail
cd /workspace

MODEL="granite3.3:2b"

echo "Installing dependencies..."
npm install

echo "Waiting for Ollama..."
for _ in $(seq 1 60); do
  if curl -fsS http://ollama:11434/api/tags >/dev/null 2>&1; then break; fi
  sleep 2
done

if curl -fsS -X POST http://ollama:11434/api/show -d "{\"name\":\"$MODEL\"}" >/dev/null 2>&1; then
  echo "Model $MODEL already present."
else
  echo "Pulling $MODEL (first download may take a few minutes)..."
  curl -fsS -X POST http://ollama:11434/api/pull -d "{\"name\":\"$MODEL\",\"stream\":false}"
  echo
fi
