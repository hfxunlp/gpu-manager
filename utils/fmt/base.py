#encoding: utf-8

from time import ctime

from cnfg import default_task

def parse_none(strin, func=None):

	return None if isinstance(strin, str) and (strin.lower() == "none") else (func(strin) if strin and (func is not None) else strin)

def parse_str_bool(strin):

	return (strin.isdigit() and int(strin) > 0) or (strin.lower() == "true")

def func_split(strin, func, spl=","):

	return [func(_.strip()) for _ in strin.split(spl) if _]

def int_split(strin, spl=","):

	return func_split(strin, int, spl=spl)

def str_none(obj, func=str):

	return "None" if obj is None else func(obj)

def str_join(obj, spl=","):

	return spl.join([str(_) for _ in obj])

def task_info(task):

	return [str(task.tid), str(task.usr), task.wkd, task.cmd, task.stdout, task.stderr, str(task.ngpu), str_none(task.force_gpuids, func=str_join), task.real_gpuid_args, str_none(task.gpuids, func=str_join), str(task.timeout), str(task.pid), str_none(task.ctime, func=ctime), str_none(task.stime, func=ctime), str_none(task.etime, func=ctime), task.status, task.email, task.desc]

def extract_create_dict(dictin, dedict=default_task):

	rsd = {}

	for _key in ("cmd", "wkd", "stdout", "stderr", "usr", "email", "desc",):
		rsd[_key] = dictin.get(_key, dedict.get(_key, ""))

	rsd["ngpu"] = str(dictin["ngpu"]) if "ngpu" in dictin else dedict.get("ngpu", "1")
	rsd["force_gpuids"] = str_none(dictin["force_gpuids"], func=str_join) if "force_gpuids" in dictin else dedict.get("force_gpuids", "None")
	rsd["real_gpuid_args"] = str_none(dictin["real_gpuid_args"], func=str_join) if "real_gpuid_args" in dictin else dedict.get("real_gpuid_args", "None")
	rsd["timeout"] = str(dictin["timeout"]) if "timeout" in dictin else dedict.get("timeout", "None")

	return rsd

def extract_update_dict(dictin, dedict=default_task):

	rsd = extract_create_dict(dictin, dedict=dedict)
	rsd["tid"] = str(dictin.get("tid", ""))

	return rsd
