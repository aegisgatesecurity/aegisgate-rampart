#!/bin/sh
# Rampart test entrypoint: starts socat forwarder, then Rampart
# socat forwards 0.0.0.0:8091 → 127.0.0.1:8092 so other containers can reach Rampart

echo "Starting socat forwarder (0.0.0.0:8091 → 127.0.0.1:8092)..."
socat TCP-LISTEN:8091,fork,reuseaddr TCP:127.0.0.1:8092 &

echo "Starting Rampart on port 8092..."
exec /usr/local/bin/rampart "$@"