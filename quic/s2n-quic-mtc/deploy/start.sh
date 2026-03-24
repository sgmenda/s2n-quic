#!/bin/sh
# Start twig in the background, then caddy in the foreground
twig --data-dir /data &
exec caddy run --config /etc/caddy/Caddyfile
