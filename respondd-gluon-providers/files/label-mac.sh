#!/bin/sh

. /lib/functions/system.sh

mac=$(get_mac_label)

if [ -z "$mac" ]; then
	if [ -f "/sys/class/net/eth0/address" ]; then
		cat /sys/class/net/eth0/address
		exit 0
	fi
fi
