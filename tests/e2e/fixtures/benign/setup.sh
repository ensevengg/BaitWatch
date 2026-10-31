#!/bin/sh
mkdir -p build node_modules/example/.vscode .venv src
printf '%s\n' built > build.txt
printf '%s\n' built > build/output.txt
printf '%s\n' installed > node_modules/example/index.js
printf '%s\n' 'Package guidance' > node_modules/example/AGENTS.md
printf '%s\n' '{}' > node_modules/example/.vscode/settings.json
printf '%s\n' isolated > .venv/pyvenv.cfg
printf '%s\n' 'print("ready")' > src/ready.py
printf '%s\n' '{"lockfileVersion":3}' > package-lock.json
