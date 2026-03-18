#!/bin/bash
# Stop all K8sGuard env servers.
pkill -f "server.app --scan-mode training" 2>/dev/null
sleep 2
remaining=$(pgrep -f "server.app --scan-mode training" | wc -l)
if [ "$remaining" -gt 0 ]; then
    pkill -9 -f "server.app --scan-mode training" 2>/dev/null
    sleep 1
fi
echo "All env servers stopped"
