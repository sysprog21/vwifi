#!/usr/bin/env bash
export DEVENVROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source $DEVENVROOT/scripts/common.sh

final_ret=0

probe_module cfg80211
if [ $? -ne 0 ]; then
    final_ret=1
fi

insert_module vwifi.ko
if [ $? -ne 0 ]; then
    final_ret=2
fi

if [ $final_ret -eq 0 ]; then
    sudo ip link set owl0 up
    sudo iw dev owl0 scan | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| tr [:lower:] [:upper:] > scan_bssid.log
    sudo iw dev owl0 connect MyHomeWiFi
    iwconfig owl0 | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret = 3
    fi
fi

if [ $final_ret -eq 0 ]; then
    remove_module vwifi
    rm scan_bssid.log connected.log
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED Reason Code: $final_ret"
echo "==== Test FAILED ===="
exit $final_ret
