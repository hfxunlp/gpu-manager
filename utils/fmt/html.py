#encoding: utf-8

from math import ceil
from time import ctime

from cnfg import num_user_line

def get_action(is_admin, usr, task, str_tid=None):

	_str_tid = str(task.tid) if str_tid is None else str_tid
	rs = ["<a href=\"/create/%s\">创建</a>" % (_str_tid,)]
	if is_admin or (usr == task.usr):
		if task.etime is None:
			if (task.stime is None) and (task.usr is not None):
				rs.append("<a href=\"/update/%s\">更新</a>" % (_str_tid,))
			rs.append("<a href=\"/cancel/%s\">取消</a>" % (_str_tid,))

	return " ".join(rs)

def task_info_html_no_action(task):

	_str_tid = str(task.tid)
	return [_str_tid, str(task.usr), task.wkd, task.cmd, task.stdout, task.stderr, str(task.ngpu), "None" if task.force_gpuids is None else ",".join([str(_) for _ in task.force_gpuids]), "None" if task.real_gpuid_args is None else task.real_gpuid_args, "None" if task.gpuids is None else ",".join([str(_) for _ in task.gpuids]), str(task.timeout), str(task.pid), "None" if task.ctime is None else ctime(task.ctime), "None" if task.stime is None else ctime(task.stime), "None" if task.etime is None else ctime(task.etime), "None" if task.status is None else task.status, task.email, task.desc]

def task_info_html(is_admin, task, usr):

	_str_tid = str(task.tid)
	return [_str_tid, str(task.usr), task.wkd, task.cmd, task.stdout, task.stderr, str(task.ngpu), "None" if task.force_gpuids is None else ",".join([str(_) for _ in task.force_gpuids]), "None" if task.real_gpuid_args is None else task.real_gpuid_args, "None" if task.gpuids is None else ",".join([str(_) for _ in task.gpuids]), str(task.timeout), str(task.pid), "None" if task.ctime is None else ctime(task.ctime), "None" if task.stime is None else ctime(task.stime), "None" if task.etime is None else ctime(task.etime), "None" if task.status is None else task.status, task.email, task.desc, get_action(is_admin, usr, task, str_tid=_str_tid)]

def build_html_table_head(headl):

	rs = ["<tr>"]
	for head in headl:
		rs.append("<th>%s</th>" % (head,))
	rs.append("</tr>")

	return rs

def build_html_table_row(row):

	rs = ["<tr>"]
	for ru in row:
		rs.append("<td>%s</td>" % (ru,))
	rs.append("</tr>")

	return rs

def build_html_user_table_row(row, is_admin=False):

	rs = ["<tr>"]
	if is_admin:
		for ru in row:
			if ru:
				_usr, _serv_usr, _priority = ru
				_note = []
				if _serv_usr != _usr:
					_note.append(_serv_usr)
				if _priority != 1.0:
					_note.append("%.2f" % (_priority,))
				rs.append("<td><a href=\"/query/%s\">%s</a>(%s) <a href=\"/setting/%s\">设置</a></td>" % (_usr, _usr, " ".join(_note), _usr,) if _note else "<td><a href=\"/query/%s\">%s</a> <a href=\"/setting/%s\">设置</a></td>" % (_usr, _usr, _usr,))
			else:
				rs.append("<td></td>")
	else:
		for ru in row:
			if ru:
				_usr, _serv_usr, _priority = ru
				rs.append("<td><a href=\"/query/%s\">%s</a></td>" % (_usr, _usr,) if _usr == _serv_usr else "<td><a href=\"/query/%s\">%s</a>(%s)</td>" % (_usr, _usr, _serv_usr,))
			else:
				rs.append("<td></td>")
	rs.append("</tr>")

	return rs

def build_html_task_table(is_admin, usr, head=("任务ID", "用户名", "工作路径", "执行命令", "标准输出文件", "标准错误文件", "显卡数量", "限制显卡ID", "传递设备ID", "显卡ID", "运行时间限制", "PID", "创建时间", "开始时间", "结束时间", "状态", "通知邮件", "任务描述", "操作",), content=None):

	rs = ["<table border=\"1\">"]
	if head is not None:
		rs.extend(build_html_table_head(head))
	if content is not None:
		for task in content:
			rs.extend(build_html_table_row(task_info_html(is_admin, task, usr)))
	rs.append("</table>")

	return "\n".join(rs)

def build_html_task_table_no_action(head=("任务ID", "用户名", "工作路径", "执行命令", "标准输出文件", "标准错误文件", "显卡数量", "限制显卡ID", "传递设备ID", "显卡ID", "运行时间限制", "PID", "创建时间", "开始时间", "结束时间", "状态", "通知邮件", "任务描述",), content=None):

	rs = ["<table border=\"1\">"]
	if head is not None:
		rs.extend(build_html_table_head(head))
	if content is not None:
		for task in content:
			rs.extend(build_html_table_row(task_info_html_no_action(task)))
	rs.append("</table>")

	return "\n".join(rs)

def build_user_table(content=None, is_admin=False):

	rs = ["<table border=\"1\">"]
	if content and (content is not None):
		sind = 0
		num_users = len(content)
		_num_user_line = int(ceil(num_user_line / 2.0)) if is_admin else num_user_line
		_pad_line = num_users > _num_user_line
		while sind < num_users:
			eind = sind + _num_user_line
			if eind <= num_users:
				rs.extend(build_html_user_table_row(content[sind:eind], is_admin=is_admin))
			else:
				_lined = content[sind:num_users]
				if _pad_line:
					_lined.extend(["" for i in range(eind - num_users)])
				rs.extend(build_html_user_table_row(_lined, is_admin=is_admin))
			sind = eind
	rs.append("</table>")

	return "\n".join(rs)
