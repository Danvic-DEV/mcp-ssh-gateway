#!/bin/sh
set -eu

KEY_FILE="/app/ssh_keys/id_ed25519"

mkdir -p "/app/ssh_keys"
chmod 700 "/app/ssh_keys"

if [ ! -f "$KEY_FILE" ]; then
  echo "No SSH key found at $KEY_FILE. Generating ed25519 key pair..."
  ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -q
fi

chmod 600 "$KEY_FILE"
if [ -f "${KEY_FILE}.pub" ]; then
  chmod 644 "${KEY_FILE}.pub"
fi

# Ensure the app uses the generated key path by default.
export SSH_KEY_FILE="${SSH_KEY_FILE:-$KEY_FILE}"

exec "$@"
