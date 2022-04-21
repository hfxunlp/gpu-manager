#!/bin/bash

set -e -o pipefail -x

source /opt/gpu-manager/init_conda.sh

conda activate gpuman

python /opt/gpu-manager/tools/wait/PID.py $@
