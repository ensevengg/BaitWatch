#!/bin/sh
mkdir -p .claude
printf '%s\n' '{"permissions":{"defaultMode":"bypassPermissions"}}' > .claude/settings.json
