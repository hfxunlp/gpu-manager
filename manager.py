#encoding: utf-8

import pickle
from collections import OrderedDict
from lzma import compress, decompress
from math import floor, inf
from multiprocessing import Process
from os import chdir, chmod, getgid, getpid, getuid, setgid, setuid, stat
from os.path import exists as fs_check, getmtime
from pwd import getpwnam
from pyhcrypt import decrypt_bytes, encrypt_bytes
from shlex import join as sh_join
from stat import S_IRGRP, S_IROTH, S_IRUSR, S_IWGRP, S_IWOTH, S_IWUSR
from subprocess import DEVNULL, STDOUT, run
from sys import exit as sys_exit
from threading import Lock, Thread
from time import sleep, time

from utils.base import get_duplicate_items, get_exp_p, map_device
from utils.cache.cust import Cache
from utils.custom_hash import hash_func
from utils.mail import send_mail_task_bg
from utils.nvsm import get_gpu_pids
from utils.prcs.base import is_alive, join
from utils.prcs.ext import kill_ptree

from cnfg import admin_passwd, aggressive_clean, cache_drop_p, default_task as cnfg_default_task, device_id_map, digest_size, max_caches, root_mode, smtp_host, smtp_passwd, smtp_port, smtp_subject, smtp_user, wait_task_cmd, wait_task_desc, wait_task_wkd

uid, gid = getuid(), getgid()
in_root_mode = (uid == 0) and root_mode

serial_func, deserial_func = pickle.dumps, pickle.loads
serial_func_txt, deserial_func_txt = repr, eval

io_dict = {DEVNULL: DEVNULL, "/dev/null": DEVNULL, "devnull": DEVNULL, STDOUT: STDOUT, "stdout": STDOUT}

_statef_permission = S_IRUSR | S_IWUSR
_done_taskf_permission = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

_ignore_check_device_ids = set(get_duplicate_items(device_id_map.values()))

def get_usr_ids(usr):

	try:
		_tmp = getpwnam(usr)
		return _tmp.pw_uid, _tmp.pw_gid
	except:
		return None, None

def can_write(fname, uid, gid):

	if uid == 0:
		return True
	s = stat(fname)
	_mode = s.st_mode
	return ((s.st_uid == uid) and (_mode & S_IWUSR)) or ((s.st_gid == gid) and (_mode & S_IWGRP)) or (_mode & S_IWOTH)

def create_file(fname, usr, passwd, uid, gid, fall_back=DEVNULL):

	if fs_check(fname):
		return fname if (uid is None) or can_write(fname, uid, gid) else fall_back
	else:
		_p = cust_run_as(["touch", fname], usr, passwd, cwd=None, timeout=None, env=None)
		if _p.returncode == 0:
			_p = cust_run_as(["chmod", "666", fname], usr, passwd, cwd=None, timeout=None, env=None)
			if _p.returncode == 0:
				return fname
		return fall_back

def save_objects_txt(fname, *inputs):

	ens = "\n".encode("utf-8")
	with open(fname, "wb") as f:
		for tmpu in inputs:
			f.write(serial_func_txt(tmpu).encode("utf-8"))
			f.write(ens)

def load_objects_txt(fname):

	rs = []
	with open(fname, "rb") as f:
		for line in f:
			tmp = line.strip()
			if tmp:
				rs.append(deserial_func_txt(tmp.decode("utf-8")))

	return tuple(rs) if len(rs) > 1 else rs[0]

def save_object_core(fname, x, ser_x=None):

	with open(fname, "wb") as f:
		f.write(encrypt_bytes(compress(serial_func(x) if ser_x is None else ser_x), admin_passwd))

def save_object(fname, x, ser_x=None):

	p = Process(target=save_object_core, args=(fname, x,), kwargs={"ser_x":ser_x})
	p.start()

	return p

def load_object(fname, return_str=False):

	with open(fname, "rb") as f:
		tmp = f.read()
	tmp = decompress(decrypt_bytes(tmp, admin_passwd))
	rs = deserial_func(tmp)

	return (rs, tmp,) if return_str else rs

def update_state_dict(srcd, ud):

	for key, value in ud.items():
		if isinstance(value, dict):
			srcd[key] = update_state_dict(srcd[key], value)
		if value or (value is None) or (value == 0):
			srcd[key] = value

	return srcd

def update_return_code(old, new):

	return old if new == 0 else new

def priority_gt(a, b):

	if a <= 0.0:
		if b <= 0.0:
			return a < b
		else:
			return True
	else:
		if b <= 0.0:
			return False
		else:
			return a > b

def cust_run(exec_cmd, stdout=DEVNULL, stderr=DEVNULL, shell=True, cwd=None, timeout=None, env=None):

	return run(exec_cmd, stdin=None, stdout=stdout, stderr=stderr, capture_output=False, shell=shell, cwd=cwd, timeout=timeout, check=False, encoding=None, errors=None, text=None, env=env, universal_newlines=None)

def cust_run_as(exec_cmd, usr, passwd, stdout=DEVNULL, stderr=DEVNULL, cwd=None, timeout=None, env=None):

	_exec_cmd = exec_cmd if isinstance(exec_cmd, str) else sh_join(exec_cmd)

	# "-P" will merge stdout and stderr to stdout
	return run(["su", "-s", "/bin/bash", usr, "-c", _exec_cmd], stdin=None, input=(passwd + "\n").encode("utf-8"), stdout=stdout, stderr=stderr, capture_output=False, shell=False, cwd=cwd, timeout=timeout, check=False, encoding=None, errors=None, text=None, env=env, universal_newlines=None)

def start_task_core(task, usr, passwd):

	_rt_code = None
	_cuda_devices_str = ",".join([str(gpuid) for gpuid in map_device(task.gpuids, device_id_map)])
	_exec_cmd = task.cmd if task.real_gpuid_args is None else "%s %s%s" % (task.cmd, task.real_gpuid_args, _cuda_devices_str,)
	_env={"CUDA_VISIBLE_DEVICES": _cuda_devices_str, "NVIDIA_VISIBLE_DEVICES": _cuda_devices_str}
	_stdout, _stderr = io_dict.get(task.stdout.lower(), task.stdout), io_dict.get(task.stderr.lower(), task.stderr)
	if not _stdout:
		_stdout = DEVNULL
	if not _stderr:
		_stderr = DEVNULL
	if (_stderr == _stdout) and (_stdout != DEVNULL):
		_stderr = STDOUT
	if (_stderr == STDOUT) and (_stdout == DEVNULL):
		_stderr = DEVNULL

	if usr is None:
		with FileList([_stdout, _stderr], "ab") as oefiles:
			p = cust_run(_exec_cmd, stdout=oefiles[0], stderr=oefiles[-1], shell=True, cwd=task.wkd, timeout=task.timeout, env=_env)
			_rt_code = update_return_code(_rt_code, p.returncode)
	else:
		if in_root_mode:
			_uid, _gid = get_usr_ids(usr)
			if _uid is not None:
				if _gid != gid:
					setgid(_gid)
				if _uid != uid:
					setuid(_uid)
				chdir(task.wkd)
				with FileList([_stdout, _stderr], "ab") as oefiles:
					p = cust_run(_exec_cmd, stdout=oefiles[0], stderr=oefiles[-1], shell=True, cwd=None, timeout=task.timeout, env=_env)
				_rt_code = update_return_code(_rt_code, p.returncode)
		else:
			chdir(task.wkd)
			_is_stdout_f, _is_stderr_f = isinstance(_stdout, str), isinstance(_stderr, str)
			if _is_stdout_f or _is_stderr_f:
				_uid, _gid = get_usr_ids(usr)
				if _is_stdout_f:
					_stdout = create_file(_stdout, usr, passwd, _uid, _gid)
				if _is_stderr_f:
					_stderr = create_file(_stderr, usr, passwd, _uid, _gid)
				if (_stderr == STDOUT) and (_stdout == DEVNULL):
					_stderr = DEVNULL
			with FileList([_stdout, _stderr], "ab") as oefiles:
				p = cust_run_as(_exec_cmd, usr, passwd, stdout=oefiles[0], stderr=oefiles[-1], cwd=None, timeout=task.timeout, env=_env)
			_rt_code = update_return_code(_rt_code, p.returncode)
			_pfiles = [_t for _t in (_stdout, _stderr,) if isinstance(_t, str)]
			if _pfiles:
				cust_run_as(["chmod", "644", *_pfiles], usr, passwd, cwd=None, timeout=None, env=None)

	return _rt_code

def start_task_core_expt(task, usr, passwd):

	_rt_code = None
	try:
		_rt_code = start_task_core(task, usr, passwd)
	except:
		_rt_code = 1
		if aggressive_clean:
			_k_pid = getpid() + 1
			kill_ptree(_k_pid, match=("su", "/bin/bash",), strict=False)
			kill_ptree(_k_pid + 1, match=task.cmd, strict=True)
	if (_rt_code is not None) and (_rt_code != 0):
		sys_exit(_rt_code)

def start_task(task, usr, passwd):

	task.stime, task.status = time(), "running"
	p = Process(target=start_task_core_expt, args=(task, usr, passwd,))
	p.start()
	task.pid = p.pid

	return task, p

def element_in(a, b):

	return any(_au in b for _au in a)

def start_thread(*args, **kwargs):

	_ = Thread(*args, **kwargs)
	_.start()

	return _

def thread_keeper_core(t, sleep_secs, *args, **kwargs):

	if t.is_alive():
		sleep(sleep_secs)
	else:
		t.join()
		t = start_thread(*args, **kwargs)

	return t

def thread_keeper(conditions, func, sleep_secs, *args, **kwargs):

	_conditions = tuple(conditions)
	_t = start_thread(*args, **kwargs)
	if len(_conditions) > 1:
		while func(_() for _ in _conditions):
			_t = thread_keeper_core(_t, sleep_secs, *args, **kwargs)
	else:
		_condition = _conditions[0]
		while _condition():
			_t = thread_keeper_core(_t, sleep_secs, *args, **kwargs)

def get_tasks_usrs(tasks):

	rs = set()
	for _ in tasks:
		_usr = _.usr
		if _usr not in rs:
			rs.add(_usr)

	return rs

class FileList(list):

	def __init__(self, files, *inputs, **kwargs):

		super(FileList, self).__init__(open(fname, *inputs, **kwargs) if isinstance(fname, str) else fname for fname in files)

	def __enter__(self):

		return self

	def __exit__(self, *inputs, **kwargs):

		for _f in self:
			if (_f != DEVNULL) and (_f != STDOUT):
				_f.close()

class DictSerial:

	def state_dict(self):

		if hasattr(self, "state_dict_ignore"):
			return OrderedDict((key, value.state_dict() if hasattr(value, "state_dict") else value,) for key, value in self.__dict__.items() if key not in self.state_dict_ignore)
		else:
			return OrderedDict((key, value.state_dict() if hasattr(value, "state_dict") else value,) for key, value in self.__dict__.items())

	def load_state_dict(self, state_dict, full_load=False):

		if hasattr(self, "pre_load_state_dict_hook"):
			self.pre_load_state_dict_hook(state_dict, full_load=full_load)

		if hasattr(self, "state_dict_ignore"):
			for key, value in state_dict.items():
				if (key in self.__dict__) and (key not in self.state_dict_ignore):
					if hasattr(self.__dict__[key], "load_state_dict"):
						self.__dict__[key] = self.__dict__[key].load_state_dict(value)
					else:
						self.__dict__[key] = value
				elif full_load:
					self.__dict__[key] = value
		else:
			for key, value in state_dict.items():
				if key in self.__dict__:
					if hasattr(self.__dict__[key], "load_state_dict"):
						self.__dict__[key] = self.__dict__[key].load_state_dict(value)
					else:
						self.__dict__[key] = value
				elif full_load:
					self.__dict__[key] = value

		return self

	def __contains__(self, key):

		return key in self.__dict__

	def accessable(self, key):

		_keys = key.split(".")
		try:
			_v = self
			for _tmp in _keys:
				if isinstance(_v, (list, tuple,)):
					_v = _v[int(_tmp)]
				elif isinstance(_v, dict):
					_v = _v[_tmp]
				else:
					if hasattr(_v, _tmp):
						_v = _v.__dict__[_tmp]
					else:
						return False
			return True
		except:
			return False

	def get(self, key, value=None):

		_keys = key.split(".")
		_v = self.__dict__.get(_keys[0], value)
		for _tmp in _keys[1:]:
			if isinstance(_v, (list, tuple,)):
				_v = _v[int(_tmp)]
			elif hasattr(_v, "get"):
				_v = _v.get(_tmp, value)
			else:
				return value
		return _v

	def set(self, key, value=None):

		_set = True
		_keys = key.split(".")
		if len(_keys) == 1:
			self.__dict__[key] = value
		else:
			_v = self
			for _tmp in _keys[:-1]:
				if isinstance(_v, (list, tuple,)):
					_v = _v[int(_tmp)]
				elif hasattr(_v, "get"):
					if _tmp in _v:
						_v = _v.get(_tmp)
					else:
						_set = False
						break
				else:
					_set = False
					break
			if _set:
				if isinstance(_v, (list, tuple,)):
					_v[int(_keys[-1])] = value
				elif isinstance(_v, dict):
					_v[_keys[-1]] = value
				elif hasattr(_v, "set"):
					_v.set(_keys[-1], value)

		return _set

	def items(self):

		return self.__dict__.items()

class LockHolder(DictSerial):

	def __init__(self, value=None):

		self.value = value
		self.lck = Lock()
		self.state_dict_ignore = set(["state_dict_ignore", "lck"])

	def __call__(self, *args):

		if args:
			with self.lck:
				self.value = args[0]
		else:
			with self.lck:
				return self.value

class User(DictSerial):

	def __init__(self, usr=None, passwd=None, serv_usr=None, serv_passwd=None, priority=None, default_task=None):

		self.usr, self.passwd, self.serv_usr, self.serv_passwd, self.priority, self.default_task = usr, hash_func(passwd, usr=usr) if passwd and isinstance(passwd, str) else passwd, serv_usr, serv_passwd, 1.0 if priority is None else priority, cnfg_default_task.copy() if default_task is None else default_task

	def verify(self, passwd):

		_ = self.passwd

		return (len(_) == digest_size) and (_ == hash_func(passwd, usr=self.usr))

	def is_unsafe(self):

		return self.verify(self.usr)

	def is_safe(self):

		return self.passwd != hash_func(self.usr, usr=self.usr)

	def lock(self):

		if len(self.passwd) == digest_size:
			self.passwd = b"#" + self.passwd

	def unlock(self):

		_ = self.passwd
		_delta = len(_) - digest_size
		if _delta > 0:
			self.passwd = _[_delta:]

class UserDict(OrderedDict):

	def state_dict(self):

		if hasattr(self, "state_dict_ignore"):
			return OrderedDict((key, value.state_dict() if hasattr(value, "state_dict") else value,) for key, value in self.items() if key not in self.state_dict_ignore)
		else:
			return OrderedDict((key, value.state_dict() if hasattr(value, "state_dict") else value,) for key, value in self.items())

	def load_state_dict(self, state_dict):

		for key, value in state_dict.items():
			self[key] = User(**value)

		return self

class Task(DictSerial):

	def __init__(self, tid=None, cmd=None, wkd=None, stdout=None, stderr=None, usr=None, ngpu=None, gpuids=None, force_gpuids=None, real_gpuid_args=None, timeout=None, email=None, desc=None, pid=None, ctime=None, stime=None, etime=None, status=None):

		self.tid, self.cmd, self.wkd, self.stdout, self.stderr, self.usr, self.ngpu, self.gpuids, self.force_gpuids, self.real_gpuid_args, self.timeout, self.email, self.desc, self.pid, self.ctime, self.stime, self.etime, self.status = tid, cmd, wkd, stdout, stderr, usr, ngpu, gpuids, force_gpuids, real_gpuid_args, timeout, email, desc, pid, time() if ctime is None else ctime, stime, etime, status

		if (self.force_gpuids is not None):
			_nforce_gpus = len(self.force_gpuids)
			if (self.ngpu is None) or (_nforce_gpus > self.ngpu):
				self.ngpu = _nforce_gpus

class TaskList(list):

	def state_dict(self):

		return [value.state_dict() if hasattr(value, "state_dict") else value for value in self]

	def load_state_dict(self, state_dict):

		self.clear()
		for su in state_dict:
			self.append(Task(**su))

		return self

class UserTaskList(OrderedDict):

	def state_dict(self):

		return OrderedDict((key, value.state_dict() if hasattr(value, "state_dict") else value,) for key, value in self.items())

	def load_state_dict(self, state_dict):

		self.clear()
		for key, value in state_dict.items():
			self[key] = TaskList().load_state_dict(value)

		return self

class Manager(DictSerial):

	def __init__(self, gpu_ids=None, sleep_secs=1.0, statef=None, done_taskf=None, save_iter=None, scheduler="balance", auto_dump_p=None, auto_dump_thres=None, cache_clean_time=None, round_tid=None):

		self.done_tasks = TaskList()
		self.done_tasks_lck = Lock()
		self.wait_tasks = TaskList() if scheduler.lower() == "fifo" else UserTaskList()
		self.wait_tasks_lck = Lock()
		self.run_tasks = OrderedDict()
		self.run_task_lck = Lock()
		self.next_task = None
		self.next_task_lck = Lock()
		self.run_new = LockHolder(True)
		self.gpu_ids = set(gpu_ids)
		self.gpu_free = [] if self.gpu_ids is None else sorted(list(self.gpu_ids))
		self.gpu_free_lck = Lock()
		self.tid = 0
		self.tid_lck = Lock()
		self.sleep_secs = sleep_secs
		self.running = LockHolder(True)
		self.statef = statef
		self.done_taskf = done_taskf
		self.save_iter = save_iter
		self.thread_saver = None
		self.save_str = None
		self.save_str_lck = Lock()
		self.save_ind = -1
		self.save_ind_lck = Lock()
		self.save_max = 2
		self.auto_dump_p = auto_dump_p
		self.auto_dump_thres = auto_dump_thres
		self.cache = Cache(max_caches=max_caches, drop_p=cache_drop_p)
		self.cache.cache_clean_time = cache_clean_time
		self.cache.thread_cleaner = None
		self.round_tid = round_tid
		self.users = UserDict()
		self.user_lck = Lock()
		self.admin_users = set()
		self.admin_lck = Lock()
		self.process_pool = []
		self.process_pool_lck = Lock()
		self.gil = Lock()
		self.ctx = OrderedDict()
		self.state_dict_ignore = set(["state_dict_ignore", "gpu_ids", "sleep_secs", "statef", "done_taskf", "save_iter", "auto_dump_p", "auto_dump_thres", "round_tid", "cache", "run_task_lck", "gpu_free_lck", "done_tasks_lck", "wait_tasks_lck", "next_task_lck", "tid_lck", "save_ind_lck", "user_lck", "admin_lck", "run_tasks", "process_pool", "process_pool_lck", "thread_launcher", "thread_consumer", "thread_saver", "thread_process_pool", "save_str", "save_str_lck", "save_ind", "gil"])

	def pre_load_state_dict_hook(self, state_dict, *args, **kwargs):

		self.wait_tasks = TaskList() if isinstance(state_dict["wait_tasks"], list) else UserTaskList()

	def authorize(self, task, usr):

		return (usr == task.usr) or (usr in self.admin_users)

	def authorize_update(self, task, usr):

		return (task.usr is not None) and self.authorize(task, usr)

	def login(self, usr, passwd):

		with self.user_lck:
			return usr in self.users and self.users[usr].verify(passwd)

	def add_user(self, usr, passwd="", serv_usr="", serv_passwd="", priority="", default_task=None):

		_reschedule = False
		with self.user_lck:
			if usr in self.users:
				_usr_priority = self.users[usr].priority
				if priority:
					_new_priority = float(priority)
					if _new_priority != _usr_priority:
						_reschedule = True
				else:
					_new_priority = _usr_priority
				self.users[usr].load_state_dict(update_state_dict(self.users[usr].state_dict(), User(usr=usr, passwd=passwd, serv_usr=serv_usr, serv_passwd=serv_passwd, priority=_new_priority, default_task=default_task).state_dict()))
				_clean_usrcreate_cache = True
			else:
				_passwd = passwd if passwd else usr
				self.users[usr] = User(usr=usr, passwd=_passwd, serv_usr=serv_usr if serv_usr else usr, serv_passwd=serv_passwd if serv_passwd else _passwd, priority=float(priority) if priority else None, default_task=default_task)
				_clean_usrcreate_cache = False
		self.cache.clear_userinfo_cache()
		if _reschedule:
			self.reschedule()
			self.cache.clear_status_cache()
		if _clean_usrcreate_cache:
			self.cache.clear_usrcreate_cache(usrs=[usr])

	def add_users(self, *usrs):

		with self.user_lck:
			for usr in usrs:
				if usr not in self.users:
					self.users[usr] = User(usr=usr, passwd=usr, serv_usr=usr, serv_passwd="", priority=None, default_task=None)
		self.cache.clear_userinfo_cache()

	def del_user(self, *usrs):

		_d_usrs = set()
		with self.gil, self.user_lck, self.admin_lck:
			for usr in usrs:
				if usr in self.users:
					del self.users[usr]
					if usr not in _d_usrs:
						_d_usrs.add(usr)
				if usr in self.admin_users:
					self.admin_users.remove(usr)
		if _d_usrs:
			self.clear_usr_tasks(_d_usrs)

	def add_admin(self, *usrs):

		_modified = []
		with self.gil, self.user_lck, self.admin_lck:
			for usr in usrs:
				if (usr in self.users) and (usr not in self.admin_users):
					self.admin_users.add(usr)
					_modified.append(usr)
		if _modified:
			self.cache.clear_userinfo_cache()
			self.cache.clear_add_admin_usrtask_cache(_modified)

	def del_admin(self, *usrs):

		with self.admin_lck:
			for usr in usrs:
				if usr in self.admin_users:
					self.admin_users.remove(usr)
		self.cache.clear_userinfo_cache()

	def lock_user(self, *usrs):

		with self.user_lck:
			for usr in usrs:
				if usr in self.users:
					self.users[usr].lock()

	def unlock_user(self, *usrs):

		with self.user_lck:
			for usr in usrs:
				if usr in self.users:
					self.users[usr].unlock()

	def clear_usr_tasks(self, usrs):

		_dtl = []
		with self.wait_tasks_lck:
			if self.wait_tasks:
				if self.is_balance_scheduler_nolck():
					for _usr in usrs:
						if _usr in self.wait_tasks:
							_dtl.extend(self.wait_tasks[_usr])
							del self.wait_tasks[_usr]
				else:
					_del_ind = []
					for _, _t in enumerate(self.wait_tasks):
						if _t.usr in usrs:
							_dtl.append(_t)
							_del_ind.append(_)
					if _del_ind:
						for _ in reversed(_del_ind):
							del self.wait_tasks[_]
		with self.next_task_lck:
			if (self.next_task is not None) and (self.next_task.usr in usrs):
				_dtl.insert(0, self.next_task)
				self.next_task = None
		ter_tasks = []
		tpl = []
		with self.run_task_lck:
			if self.run_tasks:
				for _, (p, cur_task,) in self.run_tasks.items():
					if cur_task.usr in usrs:
						tpl.append(p)
						ter_tasks.append(cur_task)
			if tpl:
				for p in tpl:
					kill_ptree(p)
			if ter_tasks:
				for cur_task in ter_tasks:
					del self.run_tasks[cur_task.tid]
		if ter_tasks:
			_rgpu = []
			for cur_task in ter_tasks:
				_rgpu.extend(cur_task.gpuids)
			if _rgpu:
				self.release_gpus(_rgpu)
			if _dtl:
				ter_tasks.extend(_dtl)
			_dtl = ter_tasks
		if _dtl:
			_etime = time()
			for _ in _dtl:
				_.etime = _etime
				_.status = "cancelled"
			self.add_done_task(*_dtl)
		self.cache.clear_userinfo_cache()
		self.cache.clear_usr_cache(usrs=usrs)

	def get_usr_priority(self, usr):

		with self.user_lck:
			if usr in self.users:
				return self.users[usr].priority

		return None

	def lock(self, *locks):

		for lck in locks:
			if hasattr(self, lck):
				_lck_obj = self.get(lck)
				if isinstance(_lck_obj, Lock) and (not _lck_obj.locked()):
					_lck_obj.acquire()

	def unlock(self, *locks):

		for lck in locks:
			if hasattr(self, lck):
				_lck_obj = self.get(lck)
				if isinstance(_lck_obj, Lock) and (_lck_obj.locked()):
					_lck_obj.release()

	def set_scheduler(self, mode):

		_clear_cache = False
		with self.wait_tasks_lck:
			is_balance_scheduler = self.is_balance_scheduler_nolck()
			if mode.lower() == "fifo":
				if is_balance_scheduler:
					_d = {}
					for _task in self.iter_wait_tasks_nolck():
						_ctime = _task.ctime
						if _ctime in _d:
							_d[_ctime].append(_task)
						else:
							_d[_ctime] = [_task]
					_rs = TaskList()
					for _key in sorted(_d.keys()):
						_rs.extend(_d[_key])
					self.wait_tasks = _rs
					_clear_cache = True
			elif not is_balance_scheduler:
				_rs = UserTaskList()
				for _task in self.iter_wait_tasks_nolck():
					_usr = _task.usr
					if _usr in _rs:
						_rs[_usr].append(_task)
					else:
						_rs[_usr] = TaskList([_task])
				self.wait_tasks = _rs
				_clear_cache = True
		if _clear_cache:
			self.cache.clear_usrtask_cache(usrs=None)

	def get_usr_gpus(self):

		rs = {}
		with self.run_task_lck:
			for (_, _task,) in self.run_tasks.values():
				_usr = _task.usr
				if _usr is not None:
					rs[_usr] = rs.get(_usr, 0) + _task.ngpu

		return rs

	def get_next_task_nolck_balance(self):

		_usr_gpus = self.get_usr_gpus()
		_c_keys = []
		_min_p, _min_p_usr = inf, []
		with self.user_lck:
			for _usr in self.wait_tasks.keys():
				if _usr in self.users:
					_usr_priority = self.users[_usr].priority
					if _usr_priority > 0.0:
						_usr_priority = (float(_usr_gpus[_usr]) / _usr_priority) if _usr in _usr_gpus else 0.0
					if _min_p > _usr_priority:
						_min_p, _min_p_usr = _usr_priority, [_usr]
					elif _min_p == _usr_priority:
						_min_p_usr.append(_usr)
				else:
					_c_keys.append(_usr)
		if _c_keys:
			for _key in _c_keys:
				del self.wait_tasks[_key]
		if _min_p_usr:
			_usr = _min_p_usr[0]
			if len(_min_p_usr) > 1:
				_min_p = min(_.ctime for _ in self.wait_tasks[_usr])
				for _tmp in _min_p_usr[1:]:
					_usr_priority = min(_.ctime for _ in self.wait_tasks[_tmp])
					if _min_p > _usr_priority:
						_usr, _min_p = _tmp, _usr_priority
			_task = self.wait_tasks[_usr].pop(0)
			if not self.wait_tasks[_usr]:
				del self.wait_tasks[_usr]
			return _task
		return None

	def get_next_task_nolck(self):

		if self.is_balance_scheduler_nolck():
			return self.get_next_task_nolck_balance()
		else:
			return self.wait_tasks.pop(0)

	def get_next_task(self):

		with self.gil, self.wait_tasks_lck:
			return self.get_next_task_nolck()

	def reschedule_nolck(self):

		if self.next_task is not None:
			_usr = self.next_task.usr
			if _usr in self.wait_tasks:
				self.wait_tasks[_usr].insert(0, self.next_task)
			else:
				self.wait_tasks[_usr] = TaskList([self.next_task])
			self.next_task = self.get_next_task_nolck_balance()

	def reschedule(self):

		with self.gil, self.wait_tasks_lck, self.next_task_lck:
			if self.is_balance_scheduler_nolck():
				self.reschedule_nolck()

	def is_balance_scheduler_nolck(self):

		return isinstance(self.wait_tasks, UserTaskList)

	def is_balance_scheduler(self):

		with self.wait_tasks_lck:
			return self.is_balance_scheduler_nolck()

	def iter_wait_tasks_nolck(self):

		if self.is_balance_scheduler_nolck():
			for _tasks in self.wait_tasks.values():
				yield from _tasks
		else:
			yield from self.wait_tasks

	def iter_wait_tasks(self):

		with self.wait_tasks_lck:
			if self.is_balance_scheduler_nolck():
				for _tasks in self.wait_tasks.values():
					yield from _tasks
			else:
				yield from self.wait_tasks

	def enum_iter_wait_tasks_nolck(self):

		if self.is_balance_scheduler_nolck():
			for _usr, _tasks in self.wait_tasks.items():
				for _i, _task in enumerate(_tasks):
					yield (_usr, _i,), _task
		else:
			yield from enumerate(self.wait_tasks)

	def enum_iter_wait_tasks_nolck_with_schedule(self):

		if self.is_balance_scheduler_nolck():
			_usr_gpus = self.get_usr_gpus()
			_c_keys = []
			_usr_priorities = {}
			with self.user_lck:
				for _usr in self.wait_tasks.keys():
					if _usr in self.users:
						_usr_priority = self.users[_usr].priority
						if _usr in _usr_gpus:
							_usr_priority = ((float(_usr_gpus[_usr]) / _usr_priority) if _usr_priority != 1.0 else float(_usr_gpus[_usr])) if _usr_priority != 0.0 else 0.0
						elif _usr_priority > 0.0:
							_usr_priority = 0.0
						if _usr_priority in _usr_priorities:
							_usr_priorities[_usr_priority].append(_usr)
						else:
							_usr_priorities[_usr_priority] = [_usr]
					else:
						_c_keys.append(_usr)
			if _c_keys:
				for _key in _c_keys:
					del self.wait_tasks[_key]
			for _ in sorted(_usr_priorities.keys()):
				_tasks = {}
				for _usr in _usr_priorities[_]:
					for _i, _task in enumerate(self.wait_tasks[_usr]):
						_ctime = _task.ctime
						if _ctime in _tasks:
							_tasks[_ctime].append(((_usr, _i,), _task,))
						else:
							_tasks[_ctime] = [((_usr, _i,), _task,)]
				for _ctime in sorted(_tasks.keys()):
					yield from _tasks[_ctime]
		else:
			yield from enumerate(self.wait_tasks)

	def enum_iter_wait_tasks(self):

		with self.wait_tasks_lck:
			if self.is_balance_scheduler_nolck():
				for _usr, _tasks in self.wait_tasks.items():
					for _i, _task in enumerate(_tasks):
						yield (_usr, _i,), _task
			else:
				yield from enumerate(self.wait_tasks)

	def pop_wait_tasks_nolck(self, i):

		if isinstance(i, tuple):
			_usr, _i = i
			rs = self.wait_tasks[_usr].pop(_i)
			if not self.wait_tasks[_usr]:
				del self.wait_tasks[_usr]
		else:
			rs = self.wait_tasks.pop(i)

		return rs

	def pop_wait_tasks(self, i):

		with self.wait_tasks_lck:
			return self.pop_wait_tasks_nolck(i)

	def get_saving_dict(self):

		run_to_done = []
		run_to_wait = []
		gpu_release = []
		with self.gil, self.tid_lck, self.wait_tasks_lck, self.next_task_lck, self.run_task_lck, self.done_tasks_lck, self.gpu_free_lck, self.user_lck, self.admin_lck:
			dict_to_save = self.state_dict()
			if self.run_tasks:
				for tid, (p, cur_task,) in self.run_tasks.items():
					if cur_task.usr is None:
						gpu_release.extend(cur_task.gpuids)
					else:
						cur_task_d = cur_task.state_dict()
						if is_alive(p):
							run_to_wait.append(cur_task_d)
						else:
							cur_task_d["etime"] = time()
							run_to_done.append(cur_task_d)
			is_balance_scheduler = self.is_balance_scheduler_nolck()

		gpu_free = dict_to_save["gpu_free"][:]
		dict_to_save_wait_tasks = dict_to_save["wait_tasks"]
		if dict_to_save["next_task"] is not None:
			if is_balance_scheduler:
				_usr = dict_to_save["next_task"]["usr"]
				if _usr in dict_to_save_wait_tasks:
					dict_to_save_wait_tasks[_usr].insert(0, dict_to_save["next_task"])
				else:
					dict_to_save_wait_tasks[_usr] = [dict_to_save["next_task"]]
			else:
				dict_to_save_wait_tasks.insert(0, dict_to_save["next_task"])
			dict_to_save["next_task"] = None
		if run_to_wait:
			if is_balance_scheduler:
				for cur_task_d in run_to_wait:
					gpu_release.extend(cur_task_d["gpuids"])
					cur_task_d["status"] = None
					cur_task_d["stime"] = None
					cur_task_d["gpuids"] = None
					_usr = cur_task_d["usr"]
					if _usr in dict_to_save_wait_tasks:
						dict_to_save_wait_tasks[_usr].insert(0, cur_task_d)
					else:
						dict_to_save_wait_tasks[_usr] = [cur_task_d]
			else:
				for cur_task_d in run_to_wait:
					gpu_release.extend(cur_task_d["gpuids"])
					cur_task_d["status"] = None
					cur_task_d["stime"] = None
					cur_task_d["gpuids"] = None
				run_to_wait.extend(dict_to_save_wait_tasks)
				dict_to_save["wait_tasks"] = run_to_wait
		if gpu_release:
			gpu_release.extend(gpu_free)
			gpu_free = gpu_release

		if run_to_done:
			for cur_task_d in run_to_done:
				gpu_free.extend(cur_task_d["gpuids"])
				cur_task_d["status"] = "done"
			dict_to_save["done_tasks"].extend(run_to_done)

		dict_to_save["gpu_free"] = gpu_free

		return dict_to_save

	def load_state(self):

		if self.statef is not None:
			_s_files = {}
			for i in range(self.save_max):
				_s_f = "%s.%d" % (self.statef, i,)
				if fs_check(_s_f):
					_m_time = getmtime(_s_f)
					if _m_time in _s_files:
						_s_files[_m_time].append((_s_f, i,))
					else:
						_s_files[_m_time] = [(_s_f, i,)]
			if _s_files:
				_dict_load = _save_ind = _save_str = None
				for _m_time in sorted(_s_files.keys(), reverse=True):
					for (_s_f, i,) in _s_files[_m_time]:
						try:
							(_dict_load, _save_str,), _save_ind = load_object(_s_f, return_str=True), i
						except:
							_dict_load = _save_ind = None
						if _dict_load is not None:
							break
					if _dict_load is not None:
						break
				if _dict_load is not None:
					self.load_state_dict(_dict_load)
					with self.save_ind_lck:
						self.save_ind = _save_ind
					if self.saver_enabled():
						with self.save_str_lck:
							self.save_str = _save_str

	def save_state(self, dict_to_save=None, ser_x=None):

		with self.save_ind_lck:
			self.save_ind = (self.save_ind + 1) % self.save_max
			_statef = "%s.%d" % (self.statef, self.save_ind,)
		cust_run(["touch", _statef], shell=False, cwd=None, timeout=None, env=None)
		chmod(_statef, _statef_permission)
		if self.statef is not None:
			_p = save_object(_statef, self.get_saving_dict() if dict_to_save is None else dict_to_save, ser_x=ser_x)
			with self.process_pool_lck:
				self.process_pool.append(_p)

	def update_state_file(self):

		_cur_state_dict = self.get_saving_dict()
		_cur_state_dict_str = serial_func(_cur_state_dict)
		_save = False
		with self.save_str_lck:
			if self.save_str is None or (self.save_str != _cur_state_dict_str):
				self.save_str = _cur_state_dict_str
				_save = True
		if _save:
			self.save_state(dict_to_save=_cur_state_dict, ser_x=_cur_state_dict_str)

	def saver(self):

		while self.running():
			sleep(self.save_iter)
			if self.running():
				self.update_state_file()

	def process_pool_handler(self):

		while self.running():
			_sleep_tag = True
			if self.running():
				with self.process_pool_lck:
					if self.process_pool:
						_ipl = []
						for _i, _p in enumerate(self.process_pool):
							if not is_alive(_p):
								_ipl.append((_i, _p,))
						if _ipl:
							for _i, _p in reversed(_ipl):
								join(_p)
								_p.close()
								del self.process_pool[_i]
							_sleep_tag = False
			if _sleep_tag:
				sleep(self.sleep_secs)
		self.clear_process_pool()

	def clear_process_pool(self):

		with self.process_pool_lck:
			if self.process_pool:
				for _p in self.process_pool:
					kill_ptree(_p)
			self.process_pool.clear()

	def send_mail(self, task, note=None):

		with self.process_pool_lck:
			self.process_pool.append(send_mail_task_bg(smtp_subject, task, note=note, host=smtp_host, port=smtp_port, user=smtp_user, passwd=smtp_passwd))

	def saver_enabled(self):

		return (self.save_iter is not None) and (self.statef is not None)

	def start(self):

		self.load_state()
		self.run_new(True)
		self.running(True)
		self.thread_launcher = Thread(target=thread_keeper, args=((self.run_new, self.running,), all, self.sleep_secs,), kwargs={"target": self.launcher})
		self.thread_consumer = Thread(target=thread_keeper, args=((self.running,), all, self.sleep_secs,), kwargs={"target": self.consumer})
		self.thread_process_pool = Thread(target=thread_keeper, args=((self.running,), all, self.sleep_secs,), kwargs={"target": self.process_pool_handler})
		self.cache.thread_cleaner = Thread(target=thread_keeper, args=((self.running,), all, self.sleep_secs,), kwargs={"target": self.cache.cleaner, "args": ((self.running,), all, self.cache.cache_clean_time,)})
		if self.saver_enabled():
			self.thread_saver = Thread(target=thread_keeper, args=((self.running,), all, self.sleep_secs,), kwargs={"target": self.saver})
			_sleep_iter = self.sleep_secs / 5
		else:
			_sleep_iter = self.sleep_secs / 4
		self.thread_launcher.start()
		sleep(_sleep_iter)
		if self.thread_saver is not None:
			self.thread_saver.start()
			sleep(_sleep_iter)
		self.cache.thread_cleaner.start()
		sleep(_sleep_iter)
		self.thread_consumer.start()
		sleep(_sleep_iter)
		self.thread_process_pool.start()

	def stop(self, force=False):

		self.run_new(False)
		self.thread_launcher.join()
		if force:
			self.terminate_processes()
		self.running(False)
		if self.cache.thread_cleaner is not None:
			self.cache.thread_cleaner.join(timeout=self.sleep_secs)
		self.thread_consumer.join()
		if self.thread_saver is not None:
			self.thread_saver.join(timeout=self.sleep_secs)
		self.thread_process_pool.join()
		if (self.cache.thread_cleaner is not None) and self.cache.thread_cleaner.is_alive():
			self.cache.clear()
		if self.thread_process_pool.is_alive():
			self.clear_process_pool()
		self.save_state()

	def add_done_task(self, *tasks):

		with self.done_tasks_lck:
			for task in tasks:
				if task.usr is not None:
					self.done_tasks.append(task)
			_num_done_tasks = len(self.done_tasks)
		if (self.auto_dump_p is not None) and (self.auto_dump_thres is not None) and (_num_done_tasks >= self.auto_dump_thres):
			self.dump_done_tasks_portion(p=get_exp_p(self.auto_dump_thres, _num_done_tasks, self.auto_dump_p))

	def write_done_tasks(self, tl):

		if self.done_taskf is not None:
			ens = "\n".encode("utf-8")
			with open(self.done_taskf, "ab") as fwrt:
				for t in tl:
					fwrt.write(serial_func_txt(t.state_dict()).encode("utf-8"))
					fwrt.write(ens)
			chmod(self.done_taskf, _done_taskf_permission)

	def dump_done_tasks_portion(self, p=None):

		_ud = {}
		_dump_l = {}
		_clear_cache_usrs = []
		with self.done_tasks_lck:
			if self.done_tasks:
				_p = get_exp_p(self.auto_dump_thres, len(self.done_tasks), self.auto_dump_p) if p is None else p
				for i, _t in enumerate(self.done_tasks):
					_usr = _t.usr
					if _usr in _ud:
						_ud[_usr].append((i, _t,))
					else:
						_ud[_usr] = [(i, _t,)]
				for _usr, _tl in _ud.items():
					_n = len(_tl)
					if _n > 1:
						_ndel = floor(_p * _n)
						if (_ndel > 0) and (_ndel < _n):
							for _i, _t in _tl[:_ndel]:
								_dump_l[_i] = _t
							_clear_cache_usrs.append(_usr)
				if _dump_l:
					_del_ind = sorted(_dump_l.keys())
					for _i in reversed(_del_ind):
						del self.done_tasks[_i]

		if _dump_l:
			self.write_done_tasks([_dump_l[_k] for _k in _del_ind])
			self.cache.clear_usrtask_cache(usrs=_clear_cache_usrs)

	def dump_done_tasks(self, k=None):

		if k is None:
			with self.done_tasks_lck:
				done_tasks = self.done_tasks
				self.done_tasks = TaskList()
		else:
			with self.done_tasks_lck:
				done_tasks = self.done_tasks[:k]
				self.done_tasks = TaskList(self.done_tasks[k:])

		if done_tasks:
			self.write_done_tasks(done_tasks)
			self.cache.clear_usrtask_cache(usrs=get_tasks_usrs(done_tasks))

	def dump_done_tasks_tid(self, *tids):

		if tids:
			_tids = set(tids)
			_dump_l = []
			_del_ind = []
			with self.done_tasks_lck:
				for _i, _t in enumerate(self.done_tasks):
					if _t.tid in _tids:
						_dump_l.append(_t)
						_del_ind.append(_i)
				if _del_ind:
					for _i in reversed(_del_ind):
						del self.done_tasks[_i]

			if _dump_l:
				self.write_done_tasks(_dump_l)
				self.cache.clear_usrtask_cache(usrs=get_tasks_usrs(_dump_l))

	def dump_usr_done_tasks(self, usr, k=None):

		_dump_l = []
		_del_ind = []
		if k is None:
			with self.done_tasks_lck:
				for i, done_task in enumerate(self.done_tasks):
					if done_task.usr == usr:
						_dump_l.append(done_task)
						_del_ind.append(i)
				if _del_ind:
					for i in reversed(_del_ind):
						del self.done_tasks[i]
		else:
			_num_find = 0
			with self.done_tasks_lck:
				for i, done_task in enumerate(self.done_tasks):
					if done_task.usr == usr:
						_dump_l.append(done_task)
						_del_ind.append(i)
						_num_find += 1
						if _num_find >= k:
							break
				if _del_ind:
					for i in reversed(_del_ind):
						del self.done_tasks[i]

		if _dump_l:
			self.write_done_tasks(_dump_l)
			self.cache.clear_usrtask_cache(usrs=[usr])

	def dump_usr_done_tasks_tid(self, usr, *tids):

		if tids:
			_tids = set(tids)
			_dump_l = []
			_del_ind = []
			with self.done_tasks_lck:
				for i, done_task in enumerate(self.done_tasks):
					if (done_task.usr == usr) and (done_task.tid in _tids):
						_dump_l.append(done_task)
						_del_ind.append(i)
				if _del_ind:
					for i in reversed(_del_ind):
						del self.done_tasks[i]

			if _dump_l:
				self.write_done_tasks(_dump_l)
				self.cache.clear_usrtask_cache(usrs=[usr])

	def add_task(self, *tasks):

		_add_tasks = self.acceptable_tasks(*tasks)
		if _add_tasks:
			_clear_cache_usrs = set()
			with self.gil, self.wait_tasks_lck:
				if self.is_balance_scheduler_nolck():
					_reschedule = False
					_usr_gpus = self.get_usr_gpus()
					_next_task_usr = None
					with self.next_task_lck:
						if self.next_task is not None:
							_next_task_usr = self.next_task.usr
					_next_task_priority = None if _next_task_usr is None else self.get_usr_priority(_next_task_usr)
					_consider_reschedule = (_next_task_usr is not None) and (_next_task_usr in _usr_gpus)
					for _task in _add_tasks:
						_usr = _task.usr
						if _usr not in self.wait_tasks:
							self.wait_tasks[_usr] = TaskList()
							if _consider_reschedule and (not _reschedule) and (_usr != _next_task_usr):
								_reschedule = True
							else:
								_usr_priority = self.get_usr_priority(_usr)
								if (_usr_priority is not None) and ((_next_task_priority is None) or priority_gt(_usr_priority, _next_task_priority)):
									_reschedule = True
						self.wait_tasks[_usr].append(_task)
						if _usr not in _clear_cache_usrs:
							_clear_cache_usrs.add(_usr)
					if _reschedule:
						with self.next_task_lck:
							self.reschedule_nolck()
				else:
					self.wait_tasks.extend(_add_tasks)
			self.cache.clear_usrtask_cache(usrs=_clear_cache_usrs)

	def gpus_available(self, task):

		if (task is None) or (task.ngpu is None):
			return True

		if task.force_gpuids is None:
			with self.gpu_free_lck:
				return len(self.gpu_free) >= task.ngpu
		else:
			with self.gpu_free_lck:
				_gpu_free_set = set(self.gpu_free)
				return (len(self.gpu_free) >= task.ngpu) and all(gpuid in _gpu_free_set for gpuid in task.force_gpuids)

	def update_gpu_free(self):

		if wait_task_cmd and wait_task_wkd and (len(self.gpu_free) > 0):
			with self.gpu_free_lck:
				_wait_task_d = {}
				for _gpuid in self.gpu_free:
					_ = device_id_map.get(_gpuid, _gpuid)
					if _ not in _ignore_check_device_ids:
						_pids = get_gpu_pids(_, timeout=self.sleep_secs)
						if _pids:
							_wait_task_d[_gpuid] = _pids
				if _wait_task_d:
					for _gpuid, _pids in _wait_task_d.items():
						self.start_task(Task(tid=- (_gpuid + 1), cmd=wait_task_cmd(_pids), wkd=wait_task_wkd, stdout="/dev/null", stderr="/dev/null", usr=None, ngpu=1, gpuids=[_gpuid], force_gpuids=[_gpuid], real_gpuid_args=None, timeout=None, email="", desc=wait_task_desc(_gpuid) if wait_task_desc else None, pid=None, ctime=None, stime=None, etime=None, status=None), None, None)
						self.gpu_free.remove(_gpuid)

	def allocate_gpus(self, task=None):

		if (task is None) or (task.ngpu is None):
			return True, task

		ngpu = task.ngpu
		if ngpu <= 0:
			task.gpuids = []
			return True, task

		self.update_gpu_free()
		if task.force_gpuids is None:
			with self.gpu_free_lck:
				if len(self.gpu_free) >= ngpu:
					task.gpuids = self.gpu_free[:ngpu]
					self.gpu_free = self.gpu_free[ngpu:]
					return True, task
		else:
			with self.gpu_free_lck:
				_gpu_free_set = set(self.gpu_free)
				if (len(self.gpu_free) >= ngpu) and all(gpuid in _gpu_free_set for gpuid in task.force_gpuids):
					task.gpuids = task.force_gpuids[:]
					for gpuid in task.gpuids:
						self.gpu_free.remove(gpuid)
					_n_force_gpus = len(task.gpuids)
					if ngpu > _n_force_gpus:
						_ngpu_more = ngpu - _n_force_gpus
						task.gpuids.extend(self.gpu_free[:_ngpu_more])
						self.gpu_free = self.gpu_free[_ngpu_more:]
					return True, task

		return False, task

	def get_done_tasks(self):

		with self.done_tasks_lck:
			done_tasks = self.done_tasks[:]

		return done_tasks

	def get_run_tasks(self):

		with self.run_task_lck:
			run_tasks = [cur_task for tid, (p, cur_task,) in self.run_tasks.items()]

		return run_tasks

	def get_wait_tasks(self):

		with self.wait_tasks_lck:
			is_balance_scheduler = self.is_balance_scheduler_nolck()
			wait_tasks = OrderedDict((key, value[:],) for key, value in self.wait_tasks.items()) if is_balance_scheduler else self.wait_tasks[:]

		_usr = None
		with self.next_task_lck:
			if self.next_task is not None:
				if is_balance_scheduler:
					_usr = self.next_task.usr
					if _usr in wait_tasks:
						wait_tasks[_usr].insert(0, self.next_task)
					else:
						wait_tasks[_usr] = [self.next_task]
				else:
					wait_tasks.insert(0, self.next_task)

		if is_balance_scheduler:
			if _usr is None:
				_rs = []
				for _v in wait_tasks.values():
					_rs.extend(_v)
			else:
				_rs = wait_tasks[_usr]
				for _k, _v in wait_tasks.items():
					if _k != _usr:
						_rs.extend(_v)
			wait_tasks = _rs

		return wait_tasks

	def get_done_tasks_user(self, user=None):

		with self.done_tasks_lck:
			done_tasks = [task for task in self.done_tasks if task.usr == user]

		return done_tasks

	def get_run_tasks_user(self, user=None):

		with self.run_task_lck:
			run_tasks = [cur_task for tid, (p, cur_task,) in self.run_tasks.items() if cur_task.usr == user]

		return run_tasks

	def get_wait_tasks_user(self, user=None):

		with self.wait_tasks_lck:
			is_balance_scheduler = self.is_balance_scheduler_nolck()
			wait_tasks = (self.wait_tasks[user][:] if user in self.wait_tasks else []) if is_balance_scheduler else [task for task in self.wait_tasks if task.usr == user]

		with self.next_task_lck:
			if (self.next_task is not None) and (self.next_task.usr == user):
				wait_tasks.insert(0, self.next_task)

		return wait_tasks

	def find_task_by_id(self, taskid, check_all=True):

		if check_all:
			with self.done_tasks_lck:
				for task in self.done_tasks:
					if task.tid == taskid:
						return task
			with self.run_task_lck:
				for tid, (p, task,) in self.run_tasks.items():
					if tid == taskid:
						return task
		with self.next_task_lck:
			if (self.next_task is not None) and (self.next_task.tid == taskid):
				return self.next_task
		for task in self.iter_wait_tasks():
			if task.tid == taskid:
				return task

		return None

	def add_gpus(self, gpuids):

		for gpuid in gpuids:
			if gpuid not in self.gpu_ids:
				self.gpu_ids.add(gpuid)
		self.update_free_gpus()

	def update_free_gpus(self):

		with self.gil, self.gpu_free_lck:
			_ = set(self.gpu_free)
			with self.run_task_lck:
				for tid, (p, task,) in self.run_tasks.items():
					gpuids = task.gpuids
					if gpuids:
						for gpuid in gpuids:
							if gpuid not in _:
								_.add(gpuid)
			for gpuid in self.gpu_ids:
				if gpuid not in _:
					self.gpu_free.append(gpuid)

	def remove_gpus(self, gpuids):

		_gpuids = set(gpuids)
		with self.gpu_free_lck:
			_free_gpus = set(self.gpu_free)
			for gpuid in _gpuids:
				if gpuid in _free_gpus:
					self.gpu_free.remove(gpuid)
					_free_gpus.remove(gpuid)
		for gpuid in _gpuids:
			if gpuid in self.gpu_ids:
				self.gpu_ids.remove(gpuid)
		with self.next_task_lck:
			if (self.next_task is not None) and (self.next_task.force_gpuids is not None) and element_in(self.next_task.force_gpuids, _gpuids):
				self.next_task.force_gpuids = None
		for wtask in self.iter_wait_tasks():
			if (wtask.force_gpuids is not None) and element_in(wtask.force_gpuids, _gpuids):
				wtask.force_gpuids = None

	def release_gpus(self, gpuids):

		if gpuids:
			with self.gpu_free_lck:
				_free_gpus = set(self.gpu_free)
				for gpuid in gpuids:
					if (gpuid in self.gpu_ids) and (gpuid not in _free_gpus):
						self.gpu_free.append(gpuid)
						_free_gpus.add(gpuid)

	def get_taskid(self):

		with self.tid_lck:
			self.tid += 1
			if (self.round_tid is not None) and (self.tid >= self.round_tid):
				self.tid = 1

			return self.tid

	def acceptable_tasks(self, *tasks):

		rs = []
		max_gpus = len(self.gpu_ids)
		for task in tasks:
			if (not task.ngpu) or task.ngpu is None or task.ngpu <= max_gpus:
				if task.force_gpuids is None:
					rs.append(task)
				else:
					_append = True
					for gid in task.force_gpuids:
						if gid not in self.gpu_ids:
							_append = False
							break
					if _append:
						rs.append(task)

		return rs

	def update_task(self, task, usr):

		if self.acceptable_tasks(task):
			_rt = None
			with self.next_task_lck:
				if (self.next_task is not None) and (self.next_task.tid == task.tid):
					if self.authorize_update(self.next_task, usr):
						self.next_task.load_state_dict(update_state_dict(self.next_task.state_dict(), task.state_dict()))
						_rt = True
					else:
						_rt = False
			if _rt is not None:
				if _rt:
					with self.gil, self.wait_tasks_lck:
						if self.is_balance_scheduler_nolck():
							self.reschedule_nolck()
					self.cache.clear_createid_cache(task.tid)
					self.cache.clear_usrtask_cache(usrs=[usr])
				return _rt
			for wtask in self.iter_wait_tasks():
				if wtask.tid == task.tid:
					if self.authorize_update(wtask, usr):
						wtask.load_state_dict(update_state_dict(wtask.state_dict(), task.state_dict()))
						_rt = True
					else:
						_rt = False
			if _rt is not None:
				if _rt:
					self.cache.clear_createid_cache(task.tid)
					self.cache.clear_usrtask_cache(usrs=[usr])
				return _rt
		return False

	def cancel_task(self, taskid, usr):

		_done_task = None
		_rt = None
		with self.next_task_lck:
			if (self.next_task is not None) and (self.next_task.tid == taskid):
				if self.authorize(self.next_task, usr):
					_done_task = self.next_task
					self.next_task = None
					_rt = True
				else:
					_rt = False
		if _rt is not None:
			if _rt:
				_done_task.etime = time()
				_done_task.status = "cancelled"
				self.add_done_task(_done_task)
				self.cache.clear_usrtask_cache(usrs=[_done_task.usr])
			return _rt
		with self.wait_tasks_lck:
			for i, wtask in self.enum_iter_wait_tasks_nolck():
				if wtask.tid == taskid:
					del_id, _done_task = i, wtask
					break
			if _done_task is not None:
				if self.authorize(_done_task, usr):
					_done_task = self.pop_wait_tasks_nolck(del_id)
					_rt = True
				else:
					_rt = False
		if _rt is not None:
			if _rt:
				_done_task.etime = time()
				_done_task.status = "cancelled"
				self.add_done_task(_done_task)
				self.cache.clear_usrtask_cache(usrs=[_done_task.usr])
			return _rt
		cancel_p = None
		_rt = False
		_update_state_file = False
		with self.run_task_lck:
			for tid, (p, cur_task,) in self.run_tasks.items():
				if tid == taskid:
					cancel_p = p
					_done_task = cur_task
					break
			if cancel_p is not None:
				if self.authorize(_done_task, usr):
					kill_ptree(cancel_p)
					del self.run_tasks[_done_task.tid]
					if not self.run_tasks:
						_update_state_file = True
					_rt = True
		if _rt:
			_done_task.etime = time()
			_done_task.status = "cancelled"
			self.release_gpus(_done_task.gpuids)
			self.add_done_task(_done_task)
			self.cache.clear_usrtask_cache(usrs=[_done_task.usr])
			if smtp_user and _done_task.email:
				self.send_mail(_done_task, note="任务已取消")
		if _update_state_file:
			with self.gil, self.wait_tasks_lck, self.next_task_lck:
				if self.wait_tasks or (self.next_task is not None):
					_update_state_file = False
		if _update_state_file:
			self.update_state_file()

		return _rt

	def move_task(self, taskid, newid):

		_wl_id = None
		with self.gil, self.wait_tasks_lck:
			for i, wtask in self.enum_iter_wait_tasks_nolck():
				if wtask.tid == taskid:
					_wl_id = i
					break
			if _wl_id is None:
				return False
			else:
				_task = self.pop_wait_tasks_nolck(_wl_id)
				_usr = _task.usr
				if _usr not in self.wait_tasks:
					self.wait_tasks[_usr] = TaskList()
				if isinstance(_wl_id, tuple):
					_insert = _check_next_task_usr = True
					if newid == 0:
						with self.next_task_lck:
							if (self.next_task is not None) and (self.next_task.usr == _usr):
								self.wait_tasks[_usr].insert(0, self.next_task)
								self.next_task = _task
								_insert = False
							else:
								_check_next_task_usr = False
					if _insert:
						if _check_next_task_usr:
							with self.next_task_lck:
								if (self.next_task is not None) and (self.next_task.usr == _usr):
									newid -= 1
						self.wait_tasks[_usr].insert(newid, _task)
				else:
					if newid == 0:
						with self.next_task_lck:
							if self.next_task is not None:
								self.wait_tasks.insert(0, self.next_task)
							self.next_task = _task
					else:
						self.wait_tasks.insert(newid - 1, _task)
		self.cache.clear_usrtask_cache(usrs=[_usr])
		return True

	def start_task(self, task, usr, passwd):

		_task, _p = start_task(task, usr, passwd)
		with self.run_task_lck:
			self.run_tasks[_task.tid] = (_p, _task,)
		if smtp_user and _task.email:
			self.send_mail(_task, note="任务已开始")
		return _task

	def launch_one_task(self, task):

		if task.usr not in self.users:
			return True

		allocated, task = self.allocate_gpus(task)
		if allocated:
			with self.user_lck:
				if task.usr in self.users:
					_tmp_user = self.users[task.usr]
					_usr, _passwd = _tmp_user.serv_usr, _tmp_user.serv_passwd
				else:
					_usr = None
			if _usr is None:
				self.release_gpus(task.gpuids)
			else:
				self.start_task(task, _usr, _passwd)
		return allocated

	def launcher(self):

		while self.run_new() and self.running():
			with self.gil, self.wait_tasks_lck:
				if self.wait_tasks:
					with self.next_task_lck:
						if self.next_task is None:
							self.next_task = self.get_next_task_nolck()
			if self.next_task is None:
				sleep(self.sleep_secs)
			else:
				while self.run_new() and (not self.gpus_available(self.next_task)):
					_sleep_tag = True
					_clean_usrs_cache = set()
					with self.next_task_lck:
						_next_task_force_gpuids = None if self.next_task is None else self.next_task.force_gpuids
					if (_next_task_force_gpuids is not None) and (len(self.gpu_free) > 0):
						with self.gil, self.wait_tasks_lck:
							if self.wait_tasks:
								_del_ind = None
								for _ind, _task in self.enum_iter_wait_tasks_nolck_with_schedule():
									if self.launch_one_task(_task):
										_del_ind = _ind
										_clean_usrs_cache.add(_task.usr)
										break
								if _del_ind is not None:
									self.pop_wait_tasks_nolck(_del_ind)
									_sleep_tag = False
					else:
						_launch_tasks = []
						with self.wait_tasks_lck:
							if self.wait_tasks:
								_del_ind = []
								for _ind, _task in self.enum_iter_wait_tasks_nolck():
									if _task.ngpu <= 0:
										_del_ind.append(_ind)
										_launch_tasks.append(_task)
								if _del_ind:
									for _ind in reversed(_del_ind):
										self.pop_wait_tasks_nolck(_ind)
						if _launch_tasks:
							for _task in _launch_tasks:
								self.launch_one_task(_task)
								_usr = _task.usr
								if _usr not in _clean_usrs_cache:
									_clean_usrs_cache.add(_usr)
							_sleep_tag = False
					if _sleep_tag:
						sleep(self.sleep_secs)
					elif _clean_usrs_cache:
						self.cache.clear_usrtask_cache(usrs=_clean_usrs_cache)
				if self.run_new():
					_clear_cache_usr = None
					with self.gil, self.next_task_lck:
						if (self.next_task is not None) and self.launch_one_task(self.next_task):
							_clear_cache_usr = self.next_task.usr
							self.next_task = None
					if _clear_cache_usr is not None:
						self.cache.clear_usrtask_cache(usrs=[_clear_cache_usr])
				else:
					with self.gil, self.wait_tasks_lck, self.next_task_lck:
						if self.next_task is not None:
							if self.is_balance_scheduler_nolck():
								_usr = self.next_task.usr
								if _usr in self.wait_tasks:
									self.wait_tasks[_usr].insert(0, self.next_task)
								else:
									self.wait_tasks[_usr] = TaskList([self.next_task])
							else:
								self.wait_tasks.insert(0, self.next_task)
						self.next_task = None

	def consumer(self):

		while self.running():
			if self.run_tasks:
				ptl = []
				_update_state_file = False
				with self.run_task_lck:
					for tid, (p, cur_task,) in self.run_tasks.items():
						if not is_alive(p):
							ptl.append((p, cur_task,))
					if ptl:
						for _p, _t in ptl:
							del self.run_tasks[_t.tid]
						if not self.run_tasks:
							_update_state_file = True
				if ptl:
					_clean_usrs_cache = set()
					_rgpu = []
					_dtl = []
					for _p, _t in ptl:
						join(_p)
						_p_exitcode = _p.exitcode
						_p.close()
						_t.etime = time()
						_t.status = "done" if (_p_exitcode is None) or (_p_exitcode == 0) else ("failed(%s)" % str(_p_exitcode))
						_rgpu.extend(_t.gpuids)
						_dtl.append(_t)
						_usr = _t.usr
						if (_usr is not None) and (_usr not in _clean_usrs_cache):
							_clean_usrs_cache.add(_usr)
						if smtp_user and _t.email:
							self.send_mail(_t, note="任务已结束")
					if _rgpu:
						self.release_gpus(_rgpu)
					if _dtl:
						self.add_done_task(*_dtl)
					if _clean_usrs_cache:
						self.cache.clear_usrtask_cache(usrs=_clean_usrs_cache)
					else:
						self.cache.clear_status_cache()
				if _update_state_file:
					with self.gil, self.wait_tasks_lck, self.next_task_lck:
						if self.wait_tasks or (self.next_task is not None):
							_update_state_file = False
				if _update_state_file:
					self.update_state_file()
			sleep(self.sleep_secs)

	def terminate_processes(self):

		with self.gil, self.wait_tasks_lck, self.next_task_lck:
			if self.next_task is not None:
				if self.is_balance_scheduler_nolck():
					_usr = self.next_task.usr
					if _usr in self.wait_tasks:
						self.wait_tasks[_usr].insert(0, self.next_task)
					else:
						self.wait_tasks[_usr] = TaskList([self.next_task])
				else:
					self.wait_tasks.insert(0, self.next_task)
			self.next_task = None

		ter_tasks = []
		tpl = []
		with self.run_task_lck:
			if self.run_tasks:
				for tid, (p, cur_task,) in self.run_tasks.items():
					if is_alive(p):
						tpl.append(p)
						ter_tasks.append(cur_task)
			if tpl:
				for p in tpl:
					kill_ptree(p)
			if ter_tasks:
				for cur_task in ter_tasks:
					del self.run_tasks[cur_task.tid]
		if ter_tasks:
			_rgpu = []
			for cur_task in ter_tasks:
				_rgpu.extend(cur_task.gpuids)
				if smtp_user and cur_task.email:
					self.send_mail(cur_task, note="任务已终止")
				cur_task.gpuids = cur_task.status = cur_task.stime = None
			if _rgpu:
				self.release_gpus(_rgpu)
			with self.wait_tasks_lck:
				is_balance_scheduler = self.is_balance_scheduler_nolck()
				_index_wait_insert = {} if is_balance_scheduler else 0
				for cur_task in ter_tasks:
					if cur_task.usr is not None:
						if is_balance_scheduler:
							_usr = cur_task.usr
							_usr_index_wait_insert = _index_wait_insert.get(_usr, 0)
							if _usr in self.wait_tasks:
								self.wait_tasks[_usr].insert(_usr_index_wait_insert, cur_task)
							else:
								self.wait_tasks[_usr] = TaskList([cur_task])
							_index_wait_insert[_usr] = _usr_index_wait_insert + 1
						else:
							self.wait_tasks.insert(_index_wait_insert, cur_task)
							_index_wait_insert += 1
			self.cache.clear_usrtask_cache(usrs=None)
