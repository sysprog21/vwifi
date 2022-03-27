#!/usr/bin/env bash

export ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source $ROOT/scripts/common.sh

final_ret=0

probe_kmod cfg80211
if [ $? -ne 0 ]; then
    final_ret=1
fi

insert_kmod vwifi.ko
if [ $? -ne 0 ]; then
    final_ret=2
fi

if [ $final_ret -eq 0 ]; then
    sudo ip link set owl0 up
    sudo iw dev owl0 scan | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| head -n 1 > scan_bssid.log
    sudo iw dev owl0 connect MyHomeWiFi
    sudo iw dev owl0 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=3
    fi
fi

if [ $final_ret -eq 0 ]; then
    remove_kmod vwifi
    rm scan_bssid.log connected.log
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED (code: $final_ret)"
echo "==== Test FAILED ===="
exit $final_ret
