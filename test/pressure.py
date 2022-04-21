#encoding: utf-8

import sys
from getpass import getpass
from requests import post, get
from json import dumps, loads
from tqdm import tqdm

host = "http://localhost:8888"

prompd = {"用户名:": "usr", "密码:": "passwd", "工作路径:": "wkd", "执行命令:": "cmd", "标准输出文件 (/dev/null不保存):": "stdout", "标准错误文件 (/dev/null不保存):": "stderr", "显卡数量:": "ngpu", "显卡ID (None不做限制):": "force_gpuids", "传递设备ID (None不传):": "real_gpuid_args", "运行时长 (None不做限制):": "timeout", "通知邮件:": "email", "任务描述:": "desc", "服务器用户名:": "serv_usr", "服务器密码:": "serv_passwd", "优先级:": "priority", "密码(不要和用户名相同，否则无法处理任务):": "new_passwd", "任务ID:": "tid"}

apid = {"create": ("用户名:", "密码:", "工作路径:", "执行命令:", "标准输出文件 (/dev/null不保存):", "标准错误文件 (/dev/null不保存):", "显卡数量:", "显卡ID (None不做限制):", "传递设备ID (None不传):", "运行时长 (None不做限制):", "通知邮件:", "任务描述:",), "update": ("任务ID:", "用户名:", "密码:", "工作路径:", "执行命令:", "标准输出文件 (/dev/null不保存):", "标准错误文件 (/dev/null不保存):", "显卡数量:", "显卡ID (None不做限制):", "传递设备ID (None不传):", "运行时长 (None不做限制):", "通知邮件:", "任务描述:",), "query": ("用户名:", "密码:",), "cancel": ("用户名:", "密码:", "任务ID:",), "setting": ("用户名:", "密码:", "密码(不要和用户名相同，否则无法处理任务):", "服务器用户名:", "服务器密码:", "优先级:", "工作路径:", "执行命令:", "标准输出文件 (/dev/null不保存):", "标准错误文件 (/dev/null不保存):", "显卡数量:", "显卡ID (None不做限制):", "传递设备ID (None不传):", "运行时长 (None不做限制):", "通知邮件:", "任务描述:",), "status": ("用户名:", "密码:",), "dump": ("用户名:", "密码:", "执行命令:",), "userinfo": ("用户名:", "密码:",), "admin": ("用户名:", "密码:", "执行命令:",)}

def handle(url, inputl, t):

	try:
		if inputl is None:
			rep = get(url=url)
		else:
			datad = {}
			for prompt in inputl:
				datad[prompd[prompt]] = getpass(prompt=prompt) if prompt.find("密码") >= 0 else input(prompt).strip()
			for i in tqdm(range(t)):
				rep = post(url=url, data=dumps(datad))
		print(loads(rep.text))
	except Exception as e:
		print(e)

if __name__ == "__main__":

	if sys.argv[1] in apid:
		handle("%s%s%s" % (host, "/api/", sys.argv[1],), apid[sys.argv[1]], int(sys.argv[-1]))
