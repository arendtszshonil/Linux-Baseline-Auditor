#!/bin/bash

# check if the script is run as root. reading security configurations requires elevation.
if [ "$EUID" -ne 0 ]; then
  echo "error: script must be run as root (use sudo)"
  exit 1
fi

echo "--- starting security baseline collection ---"

# gather all active listening network ports (tcp and udp)
echo "scanning active ports..."
ss -tulpn > active_ports.txt

echo "port scan complete. data saved to active_ports.txt"

# gather failed ssh login attempts
echo "checking for failed ssh logins..."
if [ -f /var/log/auth.log ]; then
  grep "Failed password" /var/log/auth.log > failed_ssh.txt
elif [ -f /var/log/secure ]; then
  grep "Failed password" /var/log/secure > failed_ssh.txt
else
  echo "no standard ssh auth logs found in this environment." > failed_ssh.txt
fi
echo "ssh check complete. data saved to failed_ssh.txt"

# gather running system services
echo "scanning running services..."
systemctl list-units --type=service --state=running > running_services.txt
echo "service scan complete. data saved to running_services.txt"

echo "--- collection engine finished ---"