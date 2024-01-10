#!/usr/bin/env bash

export ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source $ROOT/scripts/common.sh

final_ret=0

probe_kmod cfg80211
if [ $? -ne 0 ]; then
    final_ret=1
fi

insert_kmod vwifi.ko station=3
if [ $? -ne 0 ]; then
    final_ret=2
fi

which hostapd > /dev/null
if [ $? -ne 0 ]; then
    final_ret=3
fi

if [ $final_ret -eq 0 ]; then
    # to avoid device or resource busy error
    sleep 0.5

    # get phy number of each interface
    sudo iw dev > device.log
    vw0_phy=$(cat device.log | grep -B 1 vw0 | grep phy)
    vw0_phy=${vw0_phy/\#/}
    vw1_phy=$(cat device.log | grep -B 1 vw1 | grep phy)
    vw1_phy=${vw1_phy/\#/}
    vw2_phy=$(cat device.log | grep -B 1 vw2 | grep phy)
    vw2_phy=${vw2_phy/\#/}
    
    # create network namespaces for each phy (interface) 
    sudo ip netns add ns0
    sudo ip netns add ns1
    sudo ip netns add ns2

    # add each phy (interface) to separate network namesapces
    sudo iw phy $vw0_phy set netns name ns0
    sudo iw phy $vw1_phy set netns name ns1
    sudo iw phy $vw2_phy set netns name ns2
    
    # running hostapd on vw0, so vw0 becomes AP
    sudo ip netns exec ns0 ip link set vw0 up
    sudo ip netns exec ns0 ip link set lo up
    sudo ip netns exec ns0 hostapd -B scripts/hostapd.conf

    sudo ip netns exec ns1 ip link set vw1 up
    sudo ip netns exec ns1 ip link set lo up

    sudo ip netns exec ns2 ip link set vw2 up
    sudo ip netns exec ns2 ip link set lo up

    # assing IP address to each interface
    sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev vw0
    sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev vw1
    sudo ip netns exec ns2 ip addr add 10.0.0.3/24 dev vw2

    # ping test: STA vw1 <--> STA vw2, should fail, because they 
    # haven't connected to AP 
    echo
    echo "================================================================================"
    echo "Ping Test: STA vw1 (10.0.0.2) (not connected) <--> STA vw2 (10.0.0.3) (not connected)"
    echo
    echo "(should fail, because they haven't connnected to AP vw0 (10.0.0.1))"
    echo "(be patient, it will take some time to route...)"
    echo "================================================================================"
    sudo ip netns exec ns1 ping -c 1 10.0.0.3

    # STA vw1 performs scan and connect to TestAP
    sudo ip netns exec ns1 iw dev vw1 scan > scan_result.log
    cat scan_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| tail -n 1 > scan_bssid.log
    sudo ip netns exec ns1 iw dev vw1 connect test
    sudo ip netns exec ns1 iw dev vw1 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=4
    fi

    echo 
    echo "=================================="
    echo "vw1 connected to AP TestAP (vw0)"
    echo "=================================="

    # STA vw2 performs scan and connect to TestAP
    sudo ip netns exec ns2 iw dev vw2 scan > scan_result.log
    cat scan_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| tail -n 1 > scan_bssid.log
    sudo ip netns exec ns2 iw dev vw2 connect test
    sudo ip netns exec ns2 iw dev vw2 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=5
    fi

    echo 
    echo "=================================="
    echo "vw2 connected to AP TestAP (vw0)"
    echo "=================================="

    # ping test: STA vw1 (10.0.0.2) <--> STA vw2 (10.0.0.3),
    # should success, packet will be relayed by AP vw0 (10.0.0.1)
    echo
    echo "================================================================================"
    echo "Ping Test: STA vw1 (10.0.0.2) (connected) <--> STA vw2 (10.0.0.3) (connected)"
    echo
    echo "(should success, packet will be relay by AP vw0 (10.0.0.1))"
    echo "================================================================================"
    sudo ip netns exec ns1 ping -c 4 10.0.0.3

    # sudo ip netns exec ns1 ping -c 1 10.0.0.3
    ping_rc=$?
    if [ $ping_rc -ne 0 ]; then
        final_ret=6
    fi

    # ping test: STA vw2 (10.0.0.3) <--> AP vw0 (10.0.0.1),
    # should success, packet will directly send/receive between STA and AP
    echo
    echo "================================================================================"
    echo "Ping Test: STA vw1 (10.0.0.3) (connected) <--> AP vw0 (10.0.0.1)"
    echo
    echo "(should success, packet will directly send/receive between STA vw1 and AP vw0)"
    echo "================================================================================"
    sudo ip netns exec ns2 ping -c 4 10.0.0.1
    
    # sudo ip netns exec ns2 ping -c 4 10.0.0.1
    ping_rc=$?
    if [ $ping_rc -ne 0 ]; then
        final_ret=7
    fi

    # verify TSF (in usec)
    sudo ip netns exec ns1 iw dev vw1 scan > scan_result.log
    tsf=$(cat scan_result.log | grep "TSF" | tail -n 1 | awk '{print $2}')
    uptime=$(cat /proc/uptime | awk '{print $1}')
    uptime=$(echo "$uptime*1000000" | bc | awk -F "." '{print $1}')
    diff=$((tsf - uptime))

    # difference between tsf and uptime should less than 0.5 sec.
    if [ "${diff#-}" -gt 500000 ]; then
        final_ret=8
    fi

    # plot the distribution of RSSI of vw0
    echo -e "\n\n######## collecting RSSI information of vw0, please wait... ##########"
    vw0_mac=$(sudo ip netns exec ns0 iw dev | grep -E 'vw0$' -A 3 | grep addr | awk '{print $2}')
    counts=1000 # do get_station 1000 times

    for i in $(seq 1 1 $counts); do
        vw0_signal=$(sudo ip netns exec ns0 \
            iw dev vw0 station get $vw0_mac | grep "signal" | awk '{print $2}')
        echo $vw0_signal >> rssi.txt
    done

    python3 $ROOT/scripts/plot_rssi.py
    plot_rc=$?
    if [ $plot_rc -ne 0 ]; then
        final_ret=9
    fi

    # TestAP performs station dump
    sudo ip netns exec ns0 iw dev vw0 station dump > station_dump_result.log
    for num in {1..2}; do  
        cat station_dump_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| sed -n "${num}p" > dump_ssid.log
        sudo ip netns exec "ns${num}" iw dev | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > station_ssid.log
        DIFF=$(diff dump_ssid.log station_ssid.log)
        if [ "$DIFF" != "" ]; then
            final_ret=10
            break
        fi
    done
fi

if [ $final_ret -eq 0 ]; then
    stop_hostapd
    remove_kmod vwifi
    sudo ip netns del ns0
    sudo ip netns del ns1
    sudo ip netns del ns2
    rm scan_result.log scan_bssid.log connected.log device.log rssi.txt station_dump_result.log dump_ssid.log station_ssid.log
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED (code: $final_ret)"
echo "==== Test FAILED ===="
exit $final_ret
