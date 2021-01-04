#!/bin/bash
set -eu

SHELLPATH=`dirname $0`
SHELLPATH=$(cd $SHELLPATH; pwd)
SCHNAME='tbf'
MODNAME="sch_ftbf"

USAGE="$0 [SKETCH_DEPTH] [SKETCH_WIDTH]"

sketch_depth=4
sketch_width=1024

if (($# >= 1)); then
    sketch_depth=$1
fi

if (($# >= 2)); then
    sketch_width=$2
fi

. $SHELLPATH/utils.sh

if [[ -n "$(lsmod | grep sch_tbf)" ]]; then
    remove_sch_mod sch_tbf tbf
fi
if [[ -n "$(lsmod | grep $SCHNAME)" ]]; then
    remove_sch_mod $MODNAME $SCHNAME
fi
(cd $SHELLPATH; make)
sudo insmod $SHELLPATH/${MODNAME}.ko sketch_depth=$sketch_depth sketch_width=$sketch_width
