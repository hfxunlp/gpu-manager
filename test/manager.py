#encoding: utf-8

from manager import Task, Manager
from random import randint, sample
from time import sleep

serv_user = "test"
serv_passwd = "test"

m = Manager(gpu_ids=range(4), sleep_secs=1.0, statef=".states.pkl", done_taskf="done_tasks.txt", save_iter=5.0, cache_clean_time=5.0)

m.start()
print("started")

m.add_user("admin", "admin123", serv_user, serv_passwd)
users = ["admin"]
m.add_admin("admin")
for i in range(15):
	_user = "test%s" % (i,)
	m.add_user(_user, _user, serv_user, serv_passwd)
	users.append(_user)

tl = [Task(tid=m.get_taskid(), cmd="sleep %d" % (randint(3, 5)), wkd="/home/ano/ws/gpuman", stdout="stdout.txt", stderr="stderr.txt", usr=sample(users, 1)[0], ngpu=randint(1, 2), gpuids=None, force_gpuids=None, real_gpuid_args=None, timeout=None, email="", desc="test", pid=None, ctime=None, stime=None, etime=None, status=None) for i in range(8)]

m.add_user("notask", "notask", serv_user, serv_passwd)

m.add_task(*tl)

sleep(10)

m.dump_done_tasks(5)
print("dumped")

m.stop(force=False)
m.save_state()
