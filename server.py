#encoding: utf-8

from manager import Task, Manager, in_root_mode
from time import sleep
from threading import Thread
from gzip import compress
from flask import Flask, request, render_template, send_from_directory, session, redirect, url_for
from json import loads, dumps
import os
from urllib.parse import quote, unquote
from pyhcrypt import get_rand_bytes
from utils.custom_hash import hash_func
from utils.base import to_int
from utils.fmt.base import task_info, extract_create_dict, extract_update_dict, parse_none, parse_str_bool, int_split
from utils.fmt.html import build_html_task_table, build_user_table

from cnfg import use_port, use_gpus, admin_passwd, sleep_secs, flask_compress_level, save_every, session_life_time, refresh_time, state_file, done_task_file, auto_dump_p, auto_dump_thres, cache_life_short, cache_life_medium, cache_life_long, cache_clean_time, round_tid, secret_key_length, hash_wd, default_task

def wait_exit_core(force=False, wtime=5.0, exit_code=0):

	manager.stop(force=force)
	sleep(wtime)
	os._exit(exit_code)

def wait_exit(force=False, wtime=5.0, exit_code=0):

	t = Thread(target=wait_exit_core, kwargs={"force":force, "wtime": wtime, "exit_code": exit_code})
	t.start()

	return t

def query_user(usr, qu):

	_is_admin_page = (qu in manager.admin_users) or (qu == usr)
	_key = ("/query", usr, _is_admin_page if _is_admin_page else qu,)
	_rs = cache.get(_key, None)
	if _rs is None:
		rsd = {"ret": "完成", "usr": usr}
		if refresh_time is not None:
			rsd["refresh_time"] = refresh_time
		tmp = manager.get_done_tasks_user(usr)
		if tmp:
			rsd["done_tasks"] = build_html_task_table(_is_admin_page, qu, content=tmp)
		tmp = manager.get_run_tasks_user(usr)
		if tmp:
			rsd["run_tasks"] = build_html_task_table(_is_admin_page, qu, content=tmp)
		tmp = manager.get_wait_tasks_user(usr)
		if tmp:
			rsd["wait_tasks"] = build_html_task_table(_is_admin_page, qu, content=tmp)
		_rs = render_template("query.html", **rsd)
		cache.set(_key, _rs, cache_life_long)

	return _rs

def cancel_task(taskid, usr):

	if manager.cancel_task(taskid, usr):
		return "任务已取消."
	else:
		return "取消失败."

app = Flask(__name__)

if flask_compress_level > 0:
	@app.after_request
	def handle_gzip(response, compresslevel=flask_compress_level, minimum_size=512):

		if response.direct_passthrough:
			return response

		accept_encoding = request.headers.get("Accept-Encoding", "")
		rep_data = response.get_data()
		_rep_len = len(rep_data)

		if (response.status_code < 200) or (response.status_code >= 300) or (_rep_len < minimum_size) or ("gzip" not in accept_encoding.lower()) or ("Content-Encoding" in response.headers):
			return response

		_key = ("gzip", rep_data,)
		_rs = cache.get(_key, None)
		if _rs is None:
			_rs = compress(rep_data, compresslevel=compresslevel)
		_new_rep_len = len(_rs)
		if _new_rep_len < _rep_len:
			response.set_data(_rs)
			response.headers["Content-Encoding"] = "gzip"
			response.headers["Content-Length"] = _new_rep_len
			cache.set(_key, _rs, cache_life_medium)
		else:
			cache.set(_key, rep_data, cache_life_medium)

		return response

app.secret_key = hash_func(get_rand_bytes(secret_key_length), usr=hash_wd, digest_size=secret_key_length)
if session_life_time is not None:
	app.permanent_session_lifetime = session_life_time

@app.route("/", methods=["GET"])
def index_form():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login", code=302)
	else:
		_is_admin = usr in manager.admin_users
		_key = ("/", _is_admin,)
		_rs = cache.get(_key, None)
		if _rs is None:
			_rs = render_template("index.html", is_admin=_is_admin)
			cache.set(_key, _rs, cache_life_long)
		return _rs

@app.route("/login", methods=["GET"])
def login_form_get():

	redirect_url = request.args.get("redirect_url")
	_key = ("/login", redirect_url,)
	_rs = cache.get(_key, None)
	if _rs is None:
		_rs = render_template("login.html") if redirect_url is None else render_template("login.html", redirect_url=quote(redirect_url))
		cache.set(_key, _rs, cache_life_long)

	return _rs

@app.route("/login", methods=["POST"])
def login_form_post():

	redirect_url = request.args.get("redirect_url")
	try:
		usr, passwd = request.form["usr"], request.form["passwd"]
		if manager.login(usr, passwd):
			session["usr"] = usr
			if session_life_time is not None:
				session.permanent = True
			return redirect(("/" if manager.users[usr].is_safe() else "/setting") if redirect_url is None else unquote(redirect_url), code=302)
		else:
			if redirect_url is None:
				return render_template("login.html", ret="登录失败", **request.form)
			else:
				return render_template("login.html", ret="登录失败", redirect_url=redirect_url, **request.form)
	except Exception as e:
		return render_template("login.html", ret="登录失败,异常 %s" % (str(e),), **request.form)

@app.route("/logout", methods=["GET"])
def logout_form_get():

	if "usr" in session:
		del session["usr"]

	return redirect("/login", code=302)

@app.route("/create", methods=["POST"])
def create_form_post():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/create"),), code=302)
	elif manager.users[usr].is_unsafe():
		return redirect("/setting?redirect_url=%s" % (quote("/create"),), code=302)
	else:
		try:
			t = Task(tid=manager.get_taskid(), cmd=request.form["cmd"], wkd=request.form["wkd"], stdout=request.form["stdout"], stderr=request.form["stderr"], usr=usr, ngpu=int(request.form["ngpu"]), gpuids=None, force_gpuids=parse_none(request.form["force_gpuids"], func=int_split), real_gpuid_args=parse_none(request.form["real_gpuid_args"]), timeout=parse_none(request.form["timeout"], func=float), email=request.form["email"], desc=request.form["desc"], pid=None, ctime=None, stime=None, etime=None, status=None)
			manager.add_task(t)
			return render_template("create.html", ret="创建成功,任务ID %d" % (t.tid,), **request.form)
		except Exception as e:
			return render_template("create.html", ret="创建失败,异常 %s" % (str(e),), **request.form)

@app.route("/create", methods=["GET"])
@app.route("/create/<string:str_taskid>", methods=["GET"])
def create_form_get(str_taskid=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		_task_id = None
		if str_taskid:
			_task_id = to_int(str_taskid)
		if _task_id is None:
			_req_task = request.args.get("taskid")
			if _req_task is not None:
				_task_id = to_int(_req_task)

		if _task_id is not None:
			_task = manager.find_task_by_id(_task_id, check_all=True)
			if _task is not None:
				_key = ("/create", usr, _task_id,)
				_rs = cache.get(_key, None)
				if _rs is None:
					_rs = render_template("create.html", **extract_create_dict(_task.state_dict(), dedict=manager.users.get(usr, {"default_task": default_task}).get("default_task", default_task)))
					cache.set(_key, _rs, cache_life_short)
				return _rs

		_key = ("/create", usr,)
		_rs = cache.get(_key, None)
		if _rs is None:
			_rs = render_template("create.html", **manager.users.get(usr, {"default_task": default_task}).get("default_task", default_task))
			cache.set(_key, _rs, cache_life_long)

		return _rs

@app.route("/update", methods=["GET"])
@app.route("/update/<string:str_taskid>", methods=["GET"])
def update_form_get(str_taskid=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		_task_id = None
		if str_taskid and str_taskid.isdigit():
			_task_id = int(str_taskid)
		else:
			_req_task = request.args.get("taskid")
			if (_req_task is not None) and _req_task.isdigit():
				_task_id = int(_req_task)

		if _task_id is not None:
			_task = manager.find_task_by_id(_task_id, check_all=False)
			if (_task is not None) and ((_task.usr == usr) or (usr in manager.admin_users)):
				return render_template("update.html", **extract_update_dict(_task.state_dict(), dedict=manager.users.get(_task.usr, {"default_task": default_task}).get("default_task", default_task)))

		_key = ("/update", usr,)
		_rs = cache.get(_key, None)
		if _rs is None:
			_rs = render_template("update.html", **manager.users.get(usr, {"default_task": default_task}).get("default_task", default_task))
			cache.set(_key, _rs, cache_life_medium)

		return _rs

@app.route("/update", methods=["POST"])
def update_form_post():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/update"),), code=302)
	elif manager.users[usr].is_unsafe():
		return redirect("/setting?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		try:
			t = Task(tid=int(request.form["tid"]), cmd=request.form["cmd"], wkd=request.form["wkd"], stdout=request.form["stdout"], stderr=request.form["stderr"], usr="", ngpu=int(request.form["ngpu"]) if request.form["ngpu"] else request.form["ngpu"], gpuids=None, force_gpuids=parse_none(request.form["force_gpuids"], func=int_split), real_gpuid_args=parse_none(request.form["real_gpuid_args"]), timeout=parse_none(request.form["timeout"], func=float), email=request.form["email"], desc=request.form["desc"], pid=None, ctime=None, stime=None, etime=None, status=None)
			if manager.update_task(t, usr):
				return render_template("update.html", ret="更新成功,任务ID %d" % (t.tid,), **request.form)
			else:
				return render_template("update.html", ret="更新失败.", **request.form)
		except Exception as e:
			return render_template("update.html", ret="更新失败,异常 %s" % (str(e),), **request.form)

@app.route("/cancel", methods=["GET"])
@app.route("/cancel/<string:str_taskid>", methods=["GET"])
def cancel_form_get(str_taskid=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		_task_id, _str_taskid = None, ""
		if str_taskid:
			_task_id, _str_taskid = to_int(str_taskid), str_taskid
		if _task_id is None:
			_req_task = request.args.get("taskid")
			if _req_task is not None:
				_task_id, _str_taskid = to_int(_req_task), _req_task

		if _task_id is None:
			_key = "/cancel"
			_rs = cache.get(_key, None)
			if _rs is None:
				_rs = render_template("cancel.html")
				cache.set(_key, _rs, cache_life_long)
			return _rs
		elif manager.users[usr].is_unsafe():
			return redirect("/setting?redirect_url=%s" % (quote(request.url),), code=302)
		else:
			try:
				return render_template("cancel.html", ret=cancel_task(_task_id, usr), tid=_str_taskid)
			except Exception as e:
				return render_template("cancel.html", ret="取消失败,异常 %s" % (str(e),), tid=_str_taskid)

@app.route("/cancel", methods=["POST"])
def cancel_form_post():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/cancel"),), code=302)
	elif manager.users[usr].is_unsafe():
		return redirect("/setting?redirect_url=%s" % (quote("/cancel"),), code=302)
	else:
		try:
			return render_template("cancel.html", ret=cancel_task(int(request.form["tid"]), usr), **request.form)
		except Exception as e:
			return render_template("cancel.html", ret="取消失败,异常 %s" % (str(e),), **request.form)

@app.route("/dump", methods=["GET"])
@app.route("/dump/<string:str_cmd>", methods=["GET"])
def dump_form_get(str_cmd=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		_cmd = ""
		if str_cmd:
			_cmd = unquote(str_cmd)
		else:
			_ = request.args.get("cmd")
			if _ is not None:
				_cmd = unquote(_)
		_cmd = _cmd.strip()
		if _cmd:
			if manager.users[usr].is_unsafe():
				return redirect("/setting?redirect_url=%s" % (quote(request.url),), code=302)
			else:
				try:
					_success = False
					if _cmd == "all":
						manager.dump_usr_done_tasks(usr)
						_success = True
					elif _cmd.isdigit():
						manager.dump_usr_done_tasks(usr, k=int(_cmd))
						_success = True
					elif _cmd.startswith("task "):
						manager.dump_usr_done_tasks_tid(usr, *[int(_) for _ in _cmd.split()[1:] if _])
						_success = True
					return render_template("dump.html", ret="完成", cmd=_cmd) if _success else render_template("dump.html", ret="失败,只接受all或整数,或task taskID(s)", cmd=_cmd)
				except Exception as e:
					return render_template("dump.html", ret="取消失败,异常 %s" % (str(e),), tid=_str_taskid)
		else:
			_key = "/dump"
			_rs = cache.get(_key, None)
			if _rs is None:
				_rs = render_template("dump.html")
				cache.set(_key, _rs, cache_life_long)
			return _rs

@app.route("/dump", methods=["POST"])
def dump_form_post():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/dump"),), code=302)
	elif manager.users[usr].is_unsafe():
		return redirect("/setting?redirect_url=%s" % (quote("/dump"),), code=302)
	else:
		try:
			_cmd = request.form["cmd"].strip()
			_rt = None
			if _cmd == "all":
				manager.dump_usr_done_tasks(usr)
				_rt = render_template("dump.html", ret="完成", **request.form)
			elif _cmd.isdigit():
				manager.dump_usr_done_tasks(usr, k=int(_cmd))
				_rt = render_template("dump.html", ret="完成", **request.form)
			elif _cmd.startswith("task "):
				manager.dump_usr_done_tasks_tid(usr, *[int(_) for _ in _cmd.split()[1:] if _])
				_rt = render_template("dump.html", ret="完成", cmd=_cmd)
			if _rt is None:
				return render_template("dump.html", ret="失败,只接受all或整数,或task taskID(s)", **request.form)
			else:
				return _rt
		except Exception as e:
			return render_template("dump.html", ret="失败,异常 %s" % (str(e),), **request.form)

@app.route("/status", methods=["GET"])
def status_form_get():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/status"),), code=302)
	else:
		try:
			_is_admin = usr in manager.admin_users
			_key = ("/status", _is_admin if _is_admin else usr,)
			_rs = cache.get(_key, None)
			if _rs is None:
				rsd = {"ret": "完成"}
				if refresh_time is not None:
					rsd["refresh_time"] = refresh_time
				tmp = manager.get_done_tasks()
				if tmp:
					rsd["done_tasks"] = build_html_task_table(_is_admin, usr, content=tmp)
				tmp = manager.get_run_tasks()
				if tmp:
					rsd["run_tasks"] = build_html_task_table(_is_admin, usr, content=tmp)
				tmp = manager.get_wait_tasks()
				if tmp:
					rsd["wait_tasks"] = build_html_task_table(_is_admin, usr, content=tmp)
				_rs = render_template("status.html", **rsd)
				cache.set(_key, _rs, cache_life_long)
			return _rs
		except Exception as e:
			return render_template("status.html", ret="查询失败,异常 %s" % (str(e),))

@app.route("/userinfo", methods=["GET"])
def userinfo_form_get():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/userinfo"),), code=302)
	else:
		_is_admin = usr in manager.admin_users
		try:
			_key = ("/userinfo", _is_admin,)
			_rs = cache.get(_key, None)
			if _rs is None:
				rsd = {"ret": "完成"}
				tmp = [(_usr, _value.serv_usr, _value.priority,) for _usr, _value in manager.users.items() if _usr not in manager.admin_users]
				if tmp:
					tmp.sort()
					rsd["usrs"] = build_user_table(content=tmp, is_admin=_is_admin)
				tmp = []
				for _usr in manager.admin_users:
					_ = manager.users.get(_usr, {})
					tmp.append((_usr, _.get("serv_usr", ""), _.get("priority", 1.0),))
				if tmp:
					tmp.sort()
					rsd["admins"] = build_user_table(content=tmp, is_admin=_is_admin)
				_rs = render_template("userinfo.html", **rsd)
				cache.set(_key, _rs, cache_life_long)
			return _rs
		except Exception as e:
			return render_template("userinfo.html", ret="查询失败,异常 %s" % (str(e),))

@app.route("/query", methods=["GET"])
@app.route("/query/<string:str_user>", methods=["GET"])
def query_form_get(str_user=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		if str_user:
			_user = unquote(str_user)
		else:
			_req_user = request.args.get("user")
			if _req_user is None:
				_user = usr
			else:
				_user = unquote(_req_user)

		if _user:
			try:
				return query_user(_user, usr)
			except Exception as e:
				return render_template("query.html", ret="查询失败,异常 %s" % (str(e),), usr=_user)
		else:
			_key = "/query"
			_rs = cache.get(_key, None)
			if _rs is None:
				_rs = render_template("query.html")
				cache.set(_key, _rs, cache_life_long)
			return _rs

@app.route("/query", methods=["POST"])
def query_form_post():

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/query"),), code=302)
	else:
		try:
			return query_user(request.form["usr"] if request.form["usr"] else usr, usr)
		except Exception as e:
			return render_template("query.html", ret="查询失败,异常 %s" % (str(e),), **request.form)

@app.route("/setting", methods=["GET"])
@app.route("/setting/<string:str_user>", methods=["GET"])
def setting_form_get(str_user=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote(request.url),), code=302)
	else:
		redirect_url = request.args.get("redirect_url")
		_r_args = {}
		if redirect_url is not None:
			_r_args["redirect_url"] = quote(redirect_url)
		_usr, _in_root_mode = usr, in_root_mode
		_is_admin = usr in manager.admin_users
		if _is_admin:
			_in_root_mode = False
			_str_user = unquote(str_user)
			if _str_user and (_str_user in manager.users):
				_usr = _str_user
			else:
				_req_user = request.args.get("user")
				if _req_user is not None:
					_req_user = unquote(_req_user)
					if _req_user in manager.users:
						_usr = _req_user
		_setting_self = usr == _usr
		try:
			_user_dict = manager.users[_usr].state_dict()
			if "passwd" in _user_dict:
				del _user_dict["passwd"]
			return render_template("setting.html", in_root_mode=_in_root_mode, setting_self=_setting_self, is_admin=_is_admin, **_user_dict, **manager.users.get(_usr, {"default_task": default_task}).get("default_task", default_task), **_r_args)
		except Exception as e:
			return render_template("setting.html", ret="失败,异常 %s" % (str(e),), in_root_mode=_in_root_mode, serv_usr=manager.users[_usr].serv_usr, setting_self=_setting_self, is_admin=_is_admin, **_r_args)

@app.route("/setting", methods=["POST"])
@app.route("/setting/<string:str_user>", methods=["POST"])
def setting_form_post(str_user=""):

	usr = session.get("usr")
	if (usr is None) or (usr not in manager.users):
		return redirect("/login?redirect_url=%s" % (quote("/setting"),), code=302)
	else:
		redirect_url = request.args.get("redirect_url")
		_r_args = {}
		if redirect_url is not None:
			_r_args["redirect_url"] = quote(redirect_url)
		_usr, _in_root_mode = usr, in_root_mode
		_is_admin = usr in manager.admin_users
		if usr in manager.admin_users:
			_in_root_mode = False
			_str_user = unquote(str_user)
			if _str_user and (_str_user in manager.users):
				_usr = _str_user
			else:
				_req_user = request.args.get("user")
				if _req_user:
					_req_user = unquote(_req_user)
					if _req_user in manager.users:
						_usr = _req_user
		_setting_self = usr == _usr
		try:
			_arg_d = {"passwd": request.form["passwd"], "default_task": {k: request.form[k] for k in default_task.keys()}}
			if _is_admin:
				_arg_d["priority"] = request.form["priority"]
			if _in_root_mode:
				manager.add_user(_usr, serv_passwd=request.form["serv_passwd"], **_arg_d)
				return render_template("setting.html", ret="成功.", usr=_usr, in_root_mode=_in_root_mode, serv_usr=manager.users[_usr].serv_usr, setting_self=_setting_self, is_admin=_is_admin, **request.form, **_r_args) if (redirect_url is None) or manager.users[_usr].is_unsafe() else redirect(unquote(redirect_url), code=302)
			else:
				manager.add_user(_usr, serv_usr=request.form["serv_usr"], serv_passwd=request.form["serv_passwd"] if _setting_self else "", **_arg_d)
				return render_template("setting.html", ret="成功.", usr=_usr, in_root_mode=_in_root_mode, setting_self=_setting_self, is_admin=_is_admin, **request.form, **_r_args) if (redirect_url is None) or manager.users[_usr].is_unsafe() else redirect(unquote(redirect_url), code=302)
		except Exception as e:
			_ad = {"usr": _usr, "in_root_mode": _in_root_mode, "setting_self": _setting_self, "is_admin": _is_admin}
			if _in_root_mode:
				_ad["serv_usr"] = manager.users[_usr].serv_usr
			return render_template("setting.html", ret="失败,异常 %s" % (str(e),), **_ad, **request.form, **_r_args)

@app.route("/admin", methods=["GET"])
def admin_form_get():

	def get_admin_no_pass_page():

		_key = ("/admin", False,)
		_rs = cache.get(_key, None)
		if _rs is None:
			_rs = render_template("admin.html", show_passwd=False)
			cache.set(_key, _rs, cache_life_long)
		return _rs

	usr = session.get("usr")
	if manager.ctx["enable_super_passwd"]:
		_show_passwd = (usr is None) or (usr not in manager.admin_users)
		_key = ("/admin", _show_passwd,)
		_rs = cache.get(_key, None)
		if _rs is None:
			_rs = render_template("admin.html", show_passwd=_show_passwd)
			cache.set(_key, _rs, cache_life_long)
		return _rs
	else:
		return redirect("/login", code=302) if usr is None else (get_admin_no_pass_page() if (usr in manager.admin_users) and manager.users[usr].is_safe() else redirect("/", code=302))

@app.route("/admin", methods=["POST"])
def admin_form_post():

	usr = session.get("usr")
	show_passwd = (usr is None) or (usr not in manager.admin_users) or manager.users[usr].is_unsafe()
	try:
		if (not show_passwd) or (manager.ctx["enable_super_passwd"] and (request.form.get("passwd", None) == admin_passwd)):
			cmd = request.form["cmd"].lower()
			_success = False
			if cmd.startswith("useradd "):
				manager.add_user(*cmd.strip().split()[1:])
				_success = True
			elif cmd.startswith("addusers "):
				manager.add_users(*cmd.strip().split()[1:])
				_success = True
			elif cmd.startswith("userdel "):
				manager.del_user(*cmd.strip().split()[1:])
				_success = True
			elif cmd.startswith("suadd "):
				manager.add_admin(*cmd.strip().split()[1:])
				_success = True
			elif cmd.startswith("sudel "):
				manager.del_admin(*cmd.strip().split()[1:])
				_success = True
			elif cmd == "stop":
				manager.stop(force=False)
				_success = True
			elif cmd == "force stop":
				manager.stop(force=True)
				_success = True
			elif cmd == "exit":
				wait_exit(force=False)
				_success = True
			elif cmd == "force exit":
				wait_exit(force=True)
				_success = True
			elif cmd == "start":
				manager.start()
				_success = True
			elif cmd.startswith("dump "):
				if cmd == "dump all":
					manager.dump_done_tasks()
					_success = True
				else:
					manager.dump_done_tasks(k=int(cmd.split()[-1]))
					_success = True
			elif cmd.startswith("dumpuser "):
				_tmp = cmd.strip().split()
				usr = _tmp[1]
				if _tmp[2] == "all":
					manager.dump_usr_done_tasks(usr)
					_success = True
				else:
					manager.dump_usr_done_tasks(usr, k=int(_tmp[-1]))
					_success = True
			elif cmd.startswith("dumptask "):
				manager.dump_done_tasks_tid(*[int(_) for _ in cmd.split()[1:] if _])
				_success = True
			elif cmd == "save state":
				manager.save_state()
				_success = True
			elif cmd == "load state":
				manager.load_state()
				_success = True
			elif cmd == "save iter":
				manager.save_iter = float(cmd.split()[-1])
				_success = True
			elif cmd.startswith("move "):
				_tmp = cmd.strip().split()
				_success = manager.move_task(int(_tmp[1]), int(_tmp[-1]))
			elif cmd.startswith("add device "):
				_tmp = cmd.strip().split()
				manager.add_gpus([int(i) for i in _tmp[2:]])
				_success = True
			elif cmd.startswith("remove device "):
				_tmp = cmd.strip().split()
				manager.remove_gpus([int(i) for i in _tmp[2:]])
				_success = True
			elif cmd.startswith("set "):
				_key, _value = cmd.strip().split()[1:3]
				if manager.accessable(_key):
					if _value.lower() == "none":
						_success = manager.set(_key, None)
					else:
						_tmp = manager.get(_key)
						if isinstance(_tmp, bool):
							_success = manager.set(_key, parse_str_bool(_value))
						elif isinstance(_tmp, (int, float,)):
							_success = manager.set(_key, type(_tmp)(_value))
						elif isinstance(_tmp, str):
							_success = manager.set(_key, _value)
			elif cmd.startswith("schedule "):
				manager.set_scheduler(cmd.strip().split()[1])
				_success = True
			elif cmd == "reschedule":
				manager.reschedule()
				_success = True
			elif cmd == "clear cache":
				cache.clear()
				_success = True
			elif cmd.startswith("lock "):
				manager.lock(*cmd.strip().split()[1:])
				_success = True
			elif cmd.startswith("unlock "):
				manager.unlock(*cmd.strip().split()[1:])
				_success = True
			return render_template("admin.html", ret="完成", show_passwd=show_passwd, **request.form) if _success else render_template("admin.html", show_passwd=show_passwd, **request.form)
		return render_template("admin.html", show_passwd=show_passwd, **request.form)
	except Exception as e:
		return render_template("admin.html", ret="失败,异常 %s" % (str(e),), show_passwd=show_passwd, **request.form)

api_create_fail_dump = dumps({"ret": "创建失败."})
@app.route("/api/create", methods=["POST"])
def api_create_form_post():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd) and manager.users[usr].is_safe():
			t = Task(tid=manager.get_taskid(), cmd=request_form["cmd"], wkd=request_form["wkd"], stdout=request_form["stdout"], stderr=request_form["stderr"], usr=usr, ngpu=int(request_form["ngpu"]), gpuids=None, force_gpuids=parse_none(request_form["force_gpuids"], func=int_split), real_gpuid_args=parse_none(request_form["real_gpuid_args"]), timeout=parse_none(request_form["timeout"], func=float), email=request_form["email"], desc=request_form["desc"], pid=None, ctime=None, stime=None, etime=None, status=None)
			manager.add_task(t)
			return dumps({"ret": "创建成功,任务ID %d" % (t.tid,)})
		else:
			return api_create_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_update_fail_dump = dumps({"ret": "更新失败."})
@app.route("/api/update", methods=["POST"])
def api_update_form_post():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd) and manager.users[usr].is_safe():
			t = Task(tid=int(request_form["tid"]), cmd=request_form["cmd"], wkd=request_form["wkd"], stdout=request_form["stdout"], stderr=request_form["stderr"], usr="", ngpu=int(request_form["ngpu"]) if request_form["ngpu"] else request_form["ngpu"], gpuids=None, force_gpuids=parse_none(request_form["force_gpuids"], func=int_split), real_gpuid_args=parse_none(request_form["real_gpuid_args"]), timeout=parse_none(request_form["timeout"], func=float), email=request.form["email"], desc=request_form["desc"], pid=None, ctime=None, stime=None, etime=None, status=None)
			if manager.update_task(t, usr):
				return dumps({"ret": "更新成功,任务ID %d" % (t.tid,)})
		return api_update_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_cancel_fail_dump = dumps({"ret": "取消失败."})
@app.route("/api/cancel", methods=["POST"])
def api_cancel_form_post():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd) and manager.users[usr].is_safe():
			return dumps({"ret": cancel_task(int(request_form["tid"]), usr)})
		return api_cancel_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_dump_success_dump = dumps({"ret": "完成"})
api_dump_fail_dump = dumps({"ret": "失败,只接受all或整数,或task taskID(s)"})
@app.route("/api/dump", methods=["POST"])
def api_dump_form_post():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd) and manager.users[usr].is_safe():
			_cmd = request_form["cmd"].strip()
			_success = False
			if _cmd == "all":
				manager.dump_usr_done_tasks(usr)
				_success = True
			elif _cmd.isdigit():
				manager.dump_usr_done_tasks(usr, k=int(_cmd))
				_success = True
			elif _cmd.startswith("task "):
				manager.dump_usr_done_tasks_tid(usr, *[int(_) for _ in _cmd.split()[1:] if _])
				_success = True
			return api_dump_success_dump if _success else api_dump_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_status_fail_dump = dumps({"ret": "查询失败."})
@app.route("/api/status", methods=["POST"])
def api_status_form_get():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd):
			_key = "/api/status"
			_rs = cache.get(_key, None)
			if _rs is None:
				_rs = dumps({"done_tasks": [task_info(task) for task in manager.get_done_tasks()], "run_tasks": [task_info(task) for task in manager.get_run_tasks()], "wait_tasks": [task_info(task) for task in manager.get_wait_tasks()]})
				cache.set(_key, _rs, cache_life_long)
			return _rs
		return api_status_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_userinfo_fail_dump = dumps({"ret": "查询失败."})
@app.route("/api/userinfo", methods=["POST"])
def api_userinfo_form_get():

	def clean_user_info(usr, serv_usr, priority, is_admin):

		rs = [usr]
		if usr != serv_usr:
			rs.append(serv_usr)
		if is_admin and (priority != 1.0):
			rs.append(priority)

		return usr if len(rs) == 1 else tuple(rs)

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd):
			_is_admin = usr in manager.admin_users
			_key = ("/api/userinfo", _is_admin,)
			_rs = cache.get(_key, None)
			if _rs is None:
				rsd = {"ret": "完成"}
				tmp = [(_usr, _value.serv_usr, _value.priority) for _usr, _value in manager.users.items() if _usr not in manager.admin_users]
				if tmp:
					tmp.sort()
					rsd["usrs"] = [clean_user_info(_usr, _serv_usr, _priority, _is_admin) for _usr, _serv_usr, _priority in tmp]
				tmp = []
				for _usr in manager.admin_users:
					_ = manager.users.get(_usr, {})
					tmp.append((_usr, _.get("serv_usr", ""), _.get("priority", 1.0),))
				if tmp:
					tmp.sort()
					rsd["admins"] = [clean_user_info(_usr, _serv_usr, _priority, _is_admin) for _usr, _serv_usr, _priority in tmp]
				_rs = dumps(rsd)
				cache.set(_key, _rs, cache_life_long)
			return _rs
		return api_userinfo_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_query_fail_dump = dumps({"ret": "查询失败."})
@app.route("/api/query", methods=["POST"])
def api_query_form_post():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if manager.login(usr, passwd):
			_key = ("/api/query", usr,)
			_rs = cache.get(_key, None)
			if _rs is None:
				rsd = {}
				tmp = manager.get_done_tasks_user(usr)
				if tmp:
					rsd["done_tasks"] = [task_info(task) for task in tmp]
				tmp = manager.get_run_tasks_user(usr)
				if tmp:
					rsd["run_tasks"] = [task_info(task) for task in tmp]
				tmp = manager.get_wait_tasks_user(usr)
				if tmp:
					rsd["wait_tasks"] = [task_info(task) for task in tmp]
				_rs = dumps(rsd)
				cache.set(_key, _rs, cache_life_long)
			return _rs
		return api_query_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

api_setting_success_dump = dumps({"ret": "成功."})
api_setting_fail_dump = dumps({"ret": "设置失败."})
@app.route("/api/setting", methods=["POST"])
def api_setting_form_post():

	request_form = loads(request.get_data())
	usr, passwd = request_form["usr"], request_form["passwd"]
	if manager.login(usr, passwd):
		_is_admin = usr in manager.admin_users
		_in_root_mode = in_root_mode and (not _is_admin)
		try:
			_arg_d = {"passwd": request_form["new_passwd"], "default_task": {k: request_form[k] for k in default_task.keys()}}
			if _is_admin:
				_arg_d["priority"] = request_form["priority"]
			if _in_root_mode:
				manager.add_user(usr, serv_passwd=request_form["serv_passwd"], **_arg_d)
			else:
				manager.add_user(usr, serv_usr=request_form["serv_usr"], serv_passwd=request_form["serv_passwd"], **_arg_d)
			return api_setting_success_dump
		except Exception as e:
			return dumps({"Exception": str(e)})
	return api_setting_fail_dump

api_admin_success_dump = dumps({"ret": "完成"})
api_admin_fail_dump = dumps({})
@app.route("/api/admin", methods=["POST"])
def api_admin_form_post():

	try:
		request_form = loads(request.get_data())
		usr, passwd = request_form["usr"], request_form["passwd"]
		if (manager.ctx["enable_super_passwd"] and (request_form["passwd"] == admin_passwd)) or (manager.login(usr, passwd) and (usr in manager.admin_users) and manager.users[usr].is_safe()):
			cmd = request_form["cmd"].lower()
			if cmd.startswith("useradd "):
				manager.add_user(*cmd.strip().split()[1:])
				return api_admin_success_dump
			elif cmd.startswith("addusers "):
				manager.add_users(*cmd.strip().split()[1:])
				return api_admin_success_dump
			elif cmd.startswith("userdel "):
				manager.del_user(*cmd.strip().split()[1:])
				return api_admin_success_dump
			elif cmd.startswith("suadd "):
				manager.add_admin(*cmd.strip().split()[1:])
				return api_admin_success_dump
			elif cmd.startswith("sudel "):
				manager.del_admin(*cmd.strip().split()[1:])
				return api_admin_success_dump
			elif cmd == "stop":
				manager.stop()
				return api_admin_success_dump
			elif cmd == "force stop":
				manager.stop(force=True)
				return api_admin_success_dump
			elif cmd == "exit":
				wait_exit(force=False)
				return api_admin_success_dump
			elif cmd == "force exit":
				wait_exit(force=True)
				return api_admin_success_dump
			elif cmd == "start":
				manager.start()
				return api_admin_success_dump
			elif cmd.startswith("dump "):
				if cmd == "dump all":
					manager.dump_done_tasks()
					return api_admin_success_dump
				else:
					manager.dump_done_tasks(k=int(cmd.split()[-1]))
					return api_admin_success_dump
			elif cmd.startswith("dumpuser "):
				_tmp = cmd.strip().split()
				usr = _tmp[1]
				if _tmp[2] == "all":
					manager.dump_usr_done_tasks(usr)
					return api_admin_success_dump
				else:
					manager.dump_usr_done_tasks(usr, k=int(_tmp[-1]))
					return api_admin_success_dump
			elif cmd.startswith("dumptask "):
				manager.dump_done_tasks_tid(*[int(_) for _ in cmd.split()[1:] if _])
				return api_admin_success_dump
			elif cmd == "save state":
				manager.save_state()
				return api_admin_success_dump
			elif cmd == "load state":
				manager.load_state()
				return api_admin_success_dump
			elif cmd == "save iter":
				manager.save_iter = float(cmd.split()[-1])
				return api_admin_success_dump
			elif cmd.startswith("move "):
				_tmp = cmd.strip().split()
				if manager.move_task(int(_tmp[1]), int(_tmp[-1])):
					return api_admin_success_dump
			elif cmd.startswith("add device "):
				_tmp = cmd.strip().split()
				manager.add_gpus([int(i) for i in _tmp[2:]])
				return api_admin_success_dump
			elif cmd.startswith("remove device "):
				_tmp = cmd.strip().split()
				manager.remove_gpus([int(i) for i in _tmp[2:]])
				return api_admin_success_dump
			elif cmd.startswith("set "):
				_key, _value = cmd.strip().split()[1:3]
				if manager.accessable(_key):
					if _value.lower() == "none":
						manager.set(_key, None)
						return api_admin_success_dump
					else:
						_tmp = manager.get(_key)
						if isinstance(_tmp, bool):
							if manager.set(_key, parse_str_bool(_value)):
								return api_admin_success_dump
						elif isinstance(_tmp, (int, float,)):
							if manager.set(_key, type(_tmp)(_value)):
								return api_admin_success_dump
						elif isinstance(_tmp, str):
							if manager.set(_key, _value):
								return api_admin_success_dump
			elif cmd.startswith("schedule "):
				manager.set_scheduler(cmd.strip().split()[1])
				return api_admin_success_dump
			elif cmd == "reschedule":
				manager.reschedule()
				return api_admin_success_dump
			elif cmd == "clear cache":
				cache.clear()
				return api_admin_success_dump
			elif cmd.startswith("lock "):
				manager.lock(*cmd.strip().split()[1:])
				return api_admin_success_dump
			elif cmd.startswith("unlock "):
				manager.unlock(*cmd.strip().split()[1:])
				return api_admin_success_dump
			return api_admin_fail_dump
		return api_admin_fail_dump
	except Exception as e:
		return dumps({"Exception": str(e)})

# send everything from client as static content
@app.route("/favicon.ico")
def favicon():

	return send_from_directory(app.root_path, "favicon.ico", mimetype="image/vnd.microsoft.icon")

manager = Manager(gpu_ids=use_gpus, sleep_secs=sleep_secs, statef=state_file, done_taskf=done_task_file, save_iter=save_every, auto_dump_p=auto_dump_p, auto_dump_thres=auto_dump_thres, cache_clean_time=cache_clean_time, round_tid=round_tid)
cache = manager.cache

if __name__ == "__main__":
	manager.start()
	if ("enable_super_passwd" not in manager.ctx) or (len(manager.admin_users) == 0):
		manager.ctx["enable_super_passwd"] = True
	app.run(host="0.0.0.0", port=use_port, debug=False, threaded=True, use_reloader=False, use_debugger=False, use_evalex=False)
