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
    owl0_phy=$(cat device.log | grep -B 1 owl0 | grep phy)
    owl0_phy=${owl0_phy/\#/}
    owl1_phy=$(cat device.log | grep -B 1 owl1 | grep phy)
    owl1_phy=${owl1_phy/\#/}
    owl2_phy=$(cat device.log | grep -B 1 owl2 | grep phy)
    owl2_phy=${owl2_phy/\#/}
    
    # create network namespaces for each phy (interface) 
    sudo ip netns add ns0
    sudo ip netns add ns1
    sudo ip netns add ns2

    # add each phy (interface) to separate network namesapces
    sudo iw phy $owl0_phy set netns name ns0
    sudo iw phy $owl1_phy set netns name ns1
    sudo iw phy $owl2_phy set netns name ns2
    
    # running hostapd on owl0, so owl0 becomes AP
    sudo ip netns exec ns0 ip link set owl0 up
    sudo ip netns exec ns0 ip link set lo up
    sudo ip netns exec ns0 hostapd -B scripts/hostapd.conf

    sudo ip netns exec ns1 ip link set owl1 up
    sudo ip netns exec ns1 ip link set lo up

    sudo ip netns exec ns2 ip link set owl2 up
    sudo ip netns exec ns2 ip link set lo up

    # assing IP address to each interface
    sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev owl0
    sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev owl1
    sudo ip netns exec ns2 ip addr add 10.0.0.3/24 dev owl2

    # ping test: STA owl1 <--> STA owl2, should fail, because they 
    # haven't connected to AP 
    echo
    echo "================================================================================"
    echo "Ping Test: STA owl1 (10.0.0.2) (not connected) <--> STA owl2 (10.0.0.3) (not connected)"
    echo
    echo "(should fail, because they haven't connnected to AP owl0 (10.0.0.1))"
    echo "(be patient, it will take some time to route...)"
    echo "================================================================================"
    sudo ip netns exec ns1 ping -c 1 10.0.0.3

    # STA owl1 performs scan and connect to TestAP
    sudo ip netns exec ns1 iw dev owl1 scan > scan_result.log
    cat scan_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| tail -n 1 > scan_bssid.log
    sudo ip netns exec ns1 iw dev owl1 connect TestAP
    sudo ip netns exec ns1 iw dev owl1 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=4
    fi

    echo 
    echo "=================================="
    echo "owl1 connected to AP TestAP (owl0)"
    echo "=================================="

    # STA owl2 performs scan and connect to TestAP
    sudo ip netns exec ns2 iw dev owl2 scan > scan_result.log
    cat scan_result.log | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'| tail -n 1 > scan_bssid.log
    sudo ip netns exec ns2 iw dev owl2 connect TestAP
    sudo ip netns exec ns2 iw dev owl2 link | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > connected.log

    DIFF=$(diff connected.log scan_bssid.log)
    if [ "$DIFF" != "" ]; then
        final_ret=5
    fi

    echo 
    echo "=================================="
    echo "owl2 connected to AP TestAP (owl0)"
    echo "=================================="

    # ping test: STA owl1 (10.0.0.2) <--> STA owl2 (10.0.0.3),
    # should sucess, packet will be relayed by AP owl0 (10.0.0.1)
    echo
    echo "================================================================================"
    echo "Ping Test: STA owl1 (10.0.0.2) (connected) <--> STA owl2 (10.0.0.3) (connected)"
    echo
    echo "(should sucess, packet will be relay by AP owl0 (10.0.0.1))"
    echo "================================================================================"
    sudo ip netns exec ns1 ping -c 4 10.0.0.3

    # sudo ip netns exec ns1 ping -c 1 10.0.0.3
    ping_rc=$?
    if [ $ping_rc -ne 0 ]; then
        final_ret=6
    fi

    # ping test: STA owl2 (10.0.0.3) <--> AP owl0 (10.0.0.1),
    # should sucess, packet will directly send/receive between STA and AP
    echo
    echo "================================================================================"
    echo "Ping Test: STA owl1 (10.0.0.3) (connected) <--> AP owl0 (10.0.0.1)"
    echo
    echo "(should sucess, packet will directly send/receive between STA owl1 and AP owl0)"
    echo "================================================================================"
    sudo ip netns exec ns2 ping -c 4 10.0.0.1
    
    # sudo ip netns exec ns2 ping -c 4 10.0.0.1
    ping_rc=$?
    if [ $ping_rc -ne 0 ]; then
        final_ret=7
    fi

    # verify TSF (in usec)
    sudo ip netns exec ns1 iw dev owl1 scan > scan_result.log
    tsf=$(cat scan_result.log | grep "TSF" | tail -n 1 | awk '{print $2}')
    uptime=$(cat /proc/uptime | awk '{print $1}')
    uptime=$(echo "$uptime*1000000" | bc | awk -F "." '{print $1}')
    diff=$((tsf - uptime))

    # difference between tsf and uptime should less than 0.5 sec.
    if [ "${diff#-}" -gt 500000 ]; then
        final_ret=8
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
        plot_rc=9
    fi
fi

if [ $final_ret -eq 0 ]; then
    stop_hostapd
    remove_kmod vwifi
    sudo ip netns del ns0
    sudo ip netns del ns1
    sudo ip netns del ns2
    rm scan_result.log scan_bssid.log connected.log device.log rssi.txt 
    echo "==== Test PASSED ===="
    exit 0
fi

echo "FAILED (code: $final_ret)"
echo "==== Test FAILED ===="
exit $final_ret
