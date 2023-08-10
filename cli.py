#encoding: utf-8

import sys
from getpass import getpass
from json import dumps, loads
from requests import get, post
from urllib.parse import quote

host = "http://localhost:8888"

defaultd = {"usr": None, "passwd": None, "wkd": None, "cmd": None, "stdout": None, "stderr": None, "ngpu": None, "force_gpuids": None, "real_gpuid_args": None, "timeout": None, "email": None, "desc": None, "serv_usr": None, "serv_passwd": None, "priority": None, "new_passwd": None, "tid": None}

prompd = {"用户名:": "usr", "密码:": "passwd", "工作路径:": "wkd", "执行命令:": "cmd", "标准输出文件 (/dev/null不保存):": "stdout", "标准错误文件 (/dev/null不保存):": "stderr", "显卡数量:": "ngpu", "显卡ID (None不做限制):": "force_gpuids", "传递设备ID (None不传):": "real_gpuid_args", "运行时长 (None不做限制):": "timeout", "通知邮件:": "email", "任务描述:": "desc", "服务器用户名:": "serv_usr", "服务器密码:": "serv_passwd", "优先级:": "priority", "密码(不要和用户名相同，否则无法处理任务):": "new_passwd", "任务ID:": "tid"}

apid = {"create": ("用户名:", "密码:", "工作路径:", "执行命令:", "标准输出文件 (/dev/null不保存):", "标准错误文件 (/dev/null不保存):", "显卡数量:", "显卡ID (None不做限制):", "传递设备ID (None不传):", "运行时长 (None不做限制):", "通知邮件:", "任务描述:",), "update": ("任务ID:", "用户名:", "密码:", "工作路径:", "执行命令:", "标准输出文件 (/dev/null不保存):", "标准错误文件 (/dev/null不保存):", "显卡数量:", "显卡ID (None不做限制):", "传递设备ID (None不传):", "运行时长 (None不做限制):", "通知邮件:", "任务描述:",), "query": ("用户名:", "密码:",), "cancel": ("用户名:", "密码:", "任务ID:",), "setting": ("用户名:", "密码:", "密码(不要和用户名相同，否则无法处理任务):", "服务器用户名:", "服务器密码:", "优先级:", "工作路径:", "执行命令:", "标准输出文件 (/dev/null不保存):", "标准错误文件 (/dev/null不保存):", "显卡数量:", "显卡ID (None不做限制):", "传递设备ID (None不传):", "运行时长 (None不做限制):", "通知邮件:", "任务描述:",), "status": ("用户名:", "密码:",), "dump": ("用户名:", "密码:", "执行命令:",), "userinfo": ("用户名:", "密码:",), "admin": ("用户名:", "密码:", "执行命令:",)}

def handle(url, inputl):

	try:
		if inputl is None:
			rep = get(url=url)
		else:
			datad = {}
			for prompt in inputl:
				_key = prompd[prompt]
				_dv = defaultd.get(_key, None)
				datad[_key] = (getpass(prompt=prompt) if prompt.find("密码") >= 0 else input(prompt).strip()) if _dv is None else _dv
			rep = post(url=url, data=dumps(datad))
		print(loads(rep.text))
	except Exception as e:
		print(e)

if __name__ == "__main__":

	_arg = sys.argv[1]
	_ = _arg.find("/")
	_api_key = _arg if _ < 0 else _arg[:_]
	if _api_key in apid:
		handle("%s%s%s" % (host, "/api/", quote(_arg),), apid[_api_key])
