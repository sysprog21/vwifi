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
    # to avoid device or resource busy error
    sleep 0.5

    sudo ip link set owl0 up
    sudo iw dev owl0 scan > scan_result.log
    cat scan_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| head -n 1 > scan_bssid.log
    sudo iw dev owl0 connect MyHomeWiFi
    sudo iw dev owl0 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=3
    fi

    # verify TSF (in usec)
    tsf=$(cat scan_result.log | grep "TSF" | awk '{print $2}')
    uptime=$(cat /proc/uptime | awk '{print $1}')
    uptime=$(echo "$uptime*1000000" | bc | awk -F "." '{print $1}')
    diff=$((tsf - uptime))

    # difference between tsf and uptime should less than 0.5 sec.
    if [ "${diff#-}" -gt 500000 ]; then
        final_ret=4
    fi
fi

if [ $final_ret -eq 0 ]; then
    remove_kmod vwifi
    rm scan_result.log scan_bssid.log connected.log
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED (code: $final_ret)"
echo "==== Test FAILED ===="
exit $final_ret
