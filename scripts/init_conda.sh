#!/bin/bash

# >>> conda initialize >>>
# !! Contents within this block are managed by 'conda init' !!
__conda_setup="$('/home1/common/conda/bin/conda' 'shell.bash' 'hook' 2> /dev/null)"
if [ $? -eq 0 ]; then
	eval "$__conda_setup"
else
	if [ -f "/home1/common/conda/etc/profile.d/conda.sh" ]; then
		. "/home1/common/conda/etc/profile.d/conda.sh"
	else
		export PATH="/home1/common/conda/bin:$PATH"
	fi
fi
unset __conda_setup
# <<< conda initialize <<<
