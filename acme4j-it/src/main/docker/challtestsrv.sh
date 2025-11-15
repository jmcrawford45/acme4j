#!/bin/sh

BAMMBAMM_IP=$(hostname -i)
echo "My IP is: $BAMMBAMM_IP"

/app -defaultIPv6 "" -defaultIPv4 "$BAMMBAMM_IP"
