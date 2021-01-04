#!/bin/bash

remove_qdisc() {
    local USAGE="${FUNCNAME[0]} QDISC"
    if (($# < 1)); then
        echo $USAGE
        exit
    fi
    local qdisc="$1"
    for dev in $(ip link show | grep '^[0-9]\+' | cut -d':' -f2); do
        if [[ -n "$(tc qdisc show dev $dev | grep $qdisc)" ]]; then
            sudo tc qdisc del dev $dev root
        fi
    done
}

remove_sch_mod() {
    local USAGE="${FUNCNAME[0]} MODULE_NAME QDISC_NAME"
    if (($# < 2)); then
        echo $USAGE
        exit
    fi
    local modname="$1"
    local qdisc="$2"
    local n_used=$(lsmod | grep $modname | awk '{print $3}')
    if [[ -n "$n_used" ]]; then
        if (($n_used > 0)); then
            remove_qdisc $qdisc
        fi
        sudo rmmod $modname
    fi
}
