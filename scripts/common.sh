#! /usr/bin/env bash

function check_kmod() {
    local mod_name=$1
    lsmod | grep $mod_name > /dev/null
    if [ $? -eq 0 ]; then
        # Module found
        return 0
    fi
    return 1
}

function insert_kmod() {
    local mod_name=$1
    local param=$2
    local noko_name=$(echo $mod_name |sed s/.ko//)
    check_kmod $noko_name
    ret=$?
    if [ $ret -eq 0 ] ; then
        sudo rmmod $noko_name > /dev/null
    fi
    echo "Installing Module $mod_name"
    sudo insmod $mod_name $param
    return $(check_kmod $noko_name)
}

function probe_kmod() {
    local mod_name=$1
    check_kmod $mod_name
    ret=$?
    if [ $ret -eq 0 ] ; then
        return 0
    fi
    echo "Installing Module $mod_name"
    sudo modprobe $mod_name
    return $(check_kmod $mod_name)
}

function remove_kmod() {
    local mod_name=$1
    check_kmod $mod_name
    ret=$?
    if [ $ret -eq 1 ] ; then
        return 0
    fi
    echo "Removing Module $mod_name"
    sudo rmmod $mod_name > /dev/null
    return 0
}

function start_hostapd() {
	echo "Start Hostapd"
	which hostapd
	ret=$?
	if [ $ret -eq 1 ] ; then
		echo "Hostapd is not found"
		return 3
	fi
	sudo hostapd -B $1 > /dev/null
	return 0
}

function stop_hostapd() {
	echo "Stop Hostapd"
	sudo kill -9 $(pidof hostapd) > /dev/null
	return 0
}

function get_wiphy_name() {
    local interface_name=$1
    local wiphy_name=$(sudo iw dev $interface_name info | grep wiphy | awk '{print $2}')
    wiphy_name=$(sudo iw list | grep "wiphy index: $wiphy_name" -B 1 | grep Wiphy | awk '{print $2}')
    echo $wiphy_name
}