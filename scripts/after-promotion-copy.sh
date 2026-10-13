#!/bin/sh
# Mount this executable read-only under /hooks when using custom-script mode.
exec /usr/local/bin/after-promotion-copy "$@"
