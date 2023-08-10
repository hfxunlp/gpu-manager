#!/bin/bash

set -e -o pipefail -x

export wkpath=/opt/gpu-manager

source $wkpath/init_conda.sh

conda activate gpuman

cd $wkpath
python $wkpath/tools/nostop.py
