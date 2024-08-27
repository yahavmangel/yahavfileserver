#!/bin/sh

# Define the new nameserver
NEW_NAMESERVER="192.168.1.225"

# Replace the line with the new nameserver
sed -i "/^nameserver 127.0.0.53$/c\nameserver $NEW_NAMESERVER" /etc/resolv.conf

# If the nameserver is not found, add it at the end
grep -q "^nameserver $NEW_NAMESERVER" /etc/resolv.conf || echo "nameserver $NEW_NAMESERVER" >> /etc/resolv.conf
