#!/bin/sh
# Ordinary offline setup: resolve the registry, open TLS to it, write a marker.
# The sink never completes the handshake, so curl is expected to fail.
ip=$(hostname -i | awk '{print $1}')
base=${ip%.*}
nslookup pypi.org "$base.53" >/dev/null
curl -k -m 10 https://pypi.org/ >/dev/null 2>&1 || true
echo built > build.txt
