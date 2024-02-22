#!/usr/bin/env bash

function build_mod()
{   
    make all || exit 1
}

function run_tests()
{
    make check || exit 2
}

build_mod
# vwifi is buildable but failed to load.
#   modprobe: FATAL: Module cfg80211 not found in directory /lib/modules/5.11.0-1028-azure
#   Installing Module vwifi.ko
#   insmod: ERROR: could not insert module vwifi.ko: Unknown symbol in module
# run_tests
