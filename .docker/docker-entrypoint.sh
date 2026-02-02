#!/bin/sh
set -e

if [ -d /keys ]; then
  chown -R www-data:www-data /keys
  chmod 700 /keys
fi

exec apache2-foreground
