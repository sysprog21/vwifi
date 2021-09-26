#! /usr/bin/env bash

function check_module() {
    local mod_name=$1
    lsmod | grep $mod_name > /dev/null
    if [ $? -eq 0 ]; then
        # Module found
        return 0
    fi
    return 1
}

function insert_module() {
    local mod_name=$1
    local noko_name=$(echo $mod_name |sed s/.ko//)
    check_module $noko_name
    ret=$?
    if [ $ret -eq 0 ] ; then
        return 0
    fi
    echo "Installing Module $mod_name"
    sudo insmod $mod_name
    return $(check_module $noko_name)
}

function probe_module() {
    local mod_name=$1
    check_module $mod_name
    ret=$?
    if [ $ret -eq 0 ] ; then
        return 0
    fi
    echo "Installing Module $mod_name"
    sudo modprobe $mod_name
    return $(check_module $mod_name)
}

function remove_module() {
    local mod_name=$1
    check_module $mod_name
    ret=$?
    if [ $ret -eq 1 ] ; then
        return 0
    fi
    echo "Removing Module $mod_name"
    sudo rmmod $mod_name > /dev/null
    return 0
}
