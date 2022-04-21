#!/bin/bash

set -e -o pipefail -x

export wkpath=/opt/gpu-manager

source $wkpath/init_conda.sh

# activate your conda environment
conda activate gpuman

# run your command
cd $wkpath
ionice -c 2 -n 0 nice -n -20 python $wkpath/server.py
