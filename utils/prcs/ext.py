#encoding: utf-8

from multiprocessing import Process as py_Process
from shlex import join as sh_join
from utils.prcs.base import is_alive, join

try:
	from psutil import pid_exists, IOPRIO_CLASS_BE, Process as ps_Process, wait_procs
	_psutil_import = True
except Exception as e:
	_psutil_import = False

def renice(p, nice_value=-20, io_value=0):

	p = ps_Process(p.pid if isinstance(p, py_Process) else p)
	p.nice(nice_value)
	p.ionice(IOPRIO_CLASS_BE, value=io_value)
	for _c_p in p.children(recursive=True):
		_c_p.nice(nice_value)
		_c_p.ionice(IOPRIO_CLASS_BE, value=io_value)

def kill_ptree_ps(p, wait_time=0.5, match=None, strict=True):

	if isinstance(p, py_Process):
		pid, is_py_proc = p.pid, True
		_proc = ps_Process(pid) if pid_exists(pid) else None
	elif isinstance(p, ps_Process):
		_proc, pid, is_py_proc = p, p.pid, False
	else:
		pid, is_py_proc = p, False
		_proc = ps_Process(pid) if pid_exists(pid) else None
	if _proc is not None:
		_cs = _proc.children(recursive=True)
		_perf = True
		if match is not None:
			_p_cmd = sh_join(_proc.cmdline()) if strict else _proc.cmdline()[0]
			_perf = _p_cmd.startswith(match) if isinstance(match, str) else (_p_cmd in match)
		if _perf:
			if not is_py_proc:
				_cs.append(_proc)
			try:
				for _c_p in _cs:
					_c_p.terminate()
				gone, alive = wait_procs(_cs, timeout=wait_time)
				for _c_p in alive:
					_c_p.kill()
			except Exception as e:
				pass
	if is_py_proc:
		if is_alive(p):
			p.terminate()
		if is_alive(p):
			p.kill()
		join(p)
		p.close()

def kill_ptree_py(p, *args, **kwargs):

	if isinstance(p, Process):
		if is_alive(p):
			p.terminate()
		if is_alive(p):
			p.kill()
		join(p)
		p.close()

kill_ptree = kill_ptree_ps if _psutil_import else kill_ptree_py
