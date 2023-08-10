#encoding: utf-8

from os import getuid
from psutil import STATUS_STOPPED, STATUS_TRACING_STOP, STATUS_ZOMBIE, process_iter, wait_procs
from time import sleep

sleep_time = 60.0
wait_time = 0.5

def kill_ptree(p, wait_time=wait_time, print_func=print):

	_cs = p.children(recursive=True)
	_cs.append(p)
	try:
		for _c_p in _cs:
			_c_p.terminate()
		gone, alive = wait_procs(_cs, timeout=wait_time)
		for _c_p in alive:
			_c_p.kill()
	except Exception as e:
		if print_func is not None:
			print_func(e)

def handle(handle_zombie=True, sleep_time=sleep_time, print_func=print):

	if getuid() == 0:
		while True:
			_sleep_tag = True
			for _proc in process_iter():
				_p_status = _proc.status()
				if _p_status == STATUS_ZOMBIE:
					if handle_zombie:
						_parent = _proc.parent()
						if _parent is not None:
							try:
								_parent.resume()
							except Exception as e:
								if print_func is not None:
									print_func(e)
							_sleep_tag = False
				elif (_p_status == STATUS_STOPPED) or (_p_status == STATUS_TRACING_STOP):
					if print_func is not None:
						print_func(_proc)
					kill_ptree(_proc, print_func=print_func)
					_sleep_tag = False
			if _sleep_tag:
				sleep(sleep_time)

if __name__ == "__main__":
	handle()
