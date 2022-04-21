#encoding: utf-8

import sys
from os import getloadavg
from time import sleep

def handle(n=3, thres=0.3):

	_n, _sleep_tag = 0, True
	while _sleep_tag:
		_cpu_load = getloadavg()[0]
		if _cpu_load < thres:
			_n += 1
			if _n >= n:
				_sleep_tag = False
		else:
			_n = 0
		if _sleep_tag:
			sleep(60.0)

if __name__ == "__main__":
	_nargs = len(sys.argv)
	if _nargs > 2:
		handle(n=int(sys.argv[1]), thres=float(sys.argv[2]))
	elif _nargs == 2:
		handle(n=int(sys.argv[1]))
	else:
		handle()
