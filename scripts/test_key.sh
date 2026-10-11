#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
echo "SSH_KEY is: [$SSH_KEY]"
echo "SSH_KEY.pub is: [$SSH_KEY.pub]"
if [[ -f "$SSH_KEY.pub" ]]; then
  echo "EXISTS!"
  cat "$SSH_KEY.pub"
else
  echo "DOES NOT EXIST"
fi
