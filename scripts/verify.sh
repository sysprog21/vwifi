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

start_hostapd $ROOT/scripts/hostapd.conf
if [ $? -ne 0 ]; then
    final_ret=3
fi

if [ $final_ret -eq 0 ]; then
    # to avoid device or resource busy error
    sleep 0.5
    sudo ip link set owl0 up
    sudo ip link set owl1 up
    sudo iw dev owl0 scan > scan_result.log
    cat scan_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| tail -n 1 > scan_bssid.log
    sudo iw dev owl0 connect TestAP
    sudo iw dev owl0 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=4
    fi

    # verify TSF (in usec)
    sudo iw dev owl0 scan > scan_result.log
    tsf=$(cat scan_result.log | grep "TSF" | tail -n 1 | awk '{print $2}')
    uptime=$(cat /proc/uptime | awk '{print $1}')
    uptime=$(echo "$uptime*1000000" | bc | awk -F "." '{print $1}')
    diff=$((tsf - uptime))

    # difference between tsf and uptime should less than 0.5 sec.
    if [ "${diff#-}" -gt 500000 ]; then
        final_ret=5
    fi
    # Ping test result
    sudo iw dev > device.log
    owl0_phy=$(cat device.log | grep -B 1 owl0 | grep phy)
    owl0_phy=${owl0_phy/\#/}
    owl1_phy=$(cat device.log | grep -B 1 owl1 | grep phy)
    owl1_phy=${owl1_phy/\#/}
    
    sudo ip netns add ns0
    sudo ip netns add ns1
    sudo iw phy $owl0_phy set netns name ns0
    sudo iw phy $owl1_phy set netns name ns1

    sudo ip netns exec ns0 ip link set owl0 up
    sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev owl0

    sudo ip netns exec ns1 ip link set owl1 up
    sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev owl1

    sudo ip netns exec ns0 ping 10.0.0.2 -c 4
    ping_rc=$?
    if [ $ping_rc -ne 0 ]; then
        final_ret=6
    fi

    # plot the distribution of RSSI of owl0
    echo -e "\n\n######## collecting RSSI information of owl0, please wait... ##########"
    owl0_mac=$(sudo ip netns exec ns0 iw dev | grep -E 'owl0$' -A 3 | grep addr | awk '{print $2}')
    counts=1000 # do get_station 1000 times

    for i in $(seq 1 1 $counts); do
        owl0_signal=$(sudo ip netns exec ns0 \
            iw dev owl0 station get $owl0_mac | grep "signal" | awk '{print $2}')
        echo $owl0_signal >> rssi.txt
    done

    python3 $ROOT/scripts/plot_rssi.py
    plot_rc=$?
    if [ $plot_rc -ne 0 ]; then
        plot_rc=6
    fi
fi

if [ $final_ret -eq 0 ]; then
    stop_hostapd
    remove_kmod vwifi
    sudo ip netns del ns0
    sudo ip netns del ns1
    rm scan_result.log scan_bssid.log connected.log device.log rssi.txt 
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED (code: $final_ret)"
echo "==== Test FAILED ===="
exit $final_ret
