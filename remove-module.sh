#!/bin/bash
set -eu

SHELLPATH=`dirname $0`
SHELLPATH=$(cd $SHELLPATH; pwd)
SCHNAME='tbf'
MODNAME="sch_ftbf"
. $SHELLPATH/utils.sh

if [ -n "$(lsmod | grep $MODNAME)" ]; then
    remove_sch_mod $MODNAME $SCHNAME
fi
