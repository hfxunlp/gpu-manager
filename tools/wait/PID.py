#encoding: utf-8

import sys
from os import getuid
from math import inf
from psutil import pid_exists, Process, wait_procs, STATUS_STOPPED, STATUS_TRACING_STOP, STATUS_ZOMBIE
from time import sleep

def kill_ptree(p, wait_time=0.5):

	_cs = p.children(recursive=True)
	_cs.append(p)
	try:
		for _c_p in _cs:
			_c_p.terminate()
		gone, alive = wait_procs(_cs, timeout=wait_time)
		for _c_p in alive:
			_c_p.kill()
	except Exception as e:
		pass

def handle(pids, num_resume=1024, handle_zombie=False):

	if num_resume >= 0:
		_uid = getuid()
		_p_res = {} if num_resume < inf else False

	pidl = [(_, Process(_),) for _ in pids if pid_exists(_)]
	while pidl:
		_sleep_tag = True
		_del_l = []
		for _i, (_pid, _proc,) in enumerate(pidl):
			if _proc.is_running():
				_p_status = _proc.status()
				if _p_status == STATUS_ZOMBIE:
					_del_l.append((_i, _pid,))
					_sleep_tag = False
					if handle_zombie:
						_parent = _proc.parent()
						if _parent is not None:
							if (_uid == 0) or (_uid in _parent.uids()):
								try:
									_parent.resume()
								except Exception as e:
									pass
				elif (_p_status == STATUS_STOPPED) or (_p_status == STATUS_TRACING_STOP):
					if (_uid == 0) or (_uid in _proc.uids()):
						if num_resume == 0:
							kill_ptree(_proc)
						else:
							_resume = True
							if num_resume < inf:
								_num_p_res = _p_res.get(_pid, 0)
								if _num_p_res >= num_resume:
									kill_ptree(_proc)
									_resume = False
								else:
									_p_res[_pid] = _num_p_res + 1
							if _resume:
								try:
									_proc.resume()
								except Exception as e:
									pass
						_sleep_tag = False
					else:
						print("%d is stopped" % (_pid,))
			else:
				_del_l.append((_i, _pid,))
				_sleep_tag = False
		if _del_l:
			for _i, _pid in reversed(_del_l):
				del pidl[_i]
				if _p_res and (_pid in _p_res):
					del _p_res[_pid]
		if _sleep_tag:
			sleep(1.0)

if __name__ == "__main__":

	handle([int(i) for i in sys.argv[1:]])
