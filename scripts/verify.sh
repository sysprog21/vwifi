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
    # Ping test result
    sudo ip link set owl0sink up
    sudo ip netns add sta0
    sudo ip netns add sink
    # Create macvlan bridge mode interface.
    # All stations are directly connected to each other with a simple bridge via the physical interfaces (owl0/owl0sink).
    # After raw packet enter macvlan, it will follow normal kernel l2/l3 data path traffic process.
    #  macvlan0 10.0.0.1/24 <---> owl0 <---> vwifi driver <---> owl0sink <---> macvlan1 10.0.0.2/24
    sudo ip link add macvlan0 link owl0 type macvlan mode bridge
    sudo ip link add macvlan1 link owl0sink type macvlan mode bridge

    sudo ip link set macvlan0 netns sta0
    sudo ip link set macvlan1 netns sink

    sudo ip netns exec sta0 ip link set macvlan0 up
    sudo ip netns exec sta0 ip addr add 10.0.0.1/24 dev macvlan0

    sudo ip netns exec sink ip link set macvlan1 up
    sudo ip netns exec sink ip addr add 10.0.0.2/24 dev macvlan1

    sudo ip netns exec sta0 ping 10.0.0.2 -c 4
    ping_rc=$?
    if [ $ping_rc -ne 0 ]; then
        final_ret=5
    fi
fi

if [ $final_ret -eq 0 ]; then
    remove_kmod vwifi
    sudo ip netns delete sta0
    sudo ip netns delete sink
    rm scan_result.log scan_bssid.log connected.log
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED (code: $final_ret)"
echo "==== Test FAILED ===="
exit $final_ret
