#encoding: utf-8

from datetime import timedelta

use_port = 8888
use_gpus = list(range(4))
device_id_map = None
admin_passwd = "atestb"
sleep_secs = 1.0
save_every = 900.0

max_caches = 1024
cache_drop_p = 0.1
cache_life_short = 60.0
cache_life_medium = 1800.0
cache_life_long = 604800.0
cache_clean_time = 3000.0

session_life_time = timedelta(days=7)
refresh_time = str(int(save_every))

root_mode = False
aggressive_clean = False

state_file = ".states.pkl"
done_task_file = "done_tasks.txt"

auto_dump_p = 0.8
auto_dump_thres = 100
round_tid = None

digest_size = 64
hash_wd = admin_passwd
secret_key_length = digest_size

num_user_line = 10

flask_compress_level = 6

smtp_host = "smtp.qq.com"
smtp_port = 465
smtp_user = "test@foxmail.com"
smtp_passwd = None
smtp_subject = "服务器通知"

default_task = {"wkd": "", "cmd": "bash task.sh", "stdout": "stdout.txt", "stderr": "stderr.txt", "ngpu": "1", "force_gpuids": "None", "real_gpuid_args": "None", "timeout": "None", "email": "", "desc": ""}

wait_task_wkd = "/opt/gpu-manager"
wait_task_cmd = lambda pids: "bash %s/wait_pid.sh %s" % (wait_task_wkd, " ".join(str(_pid) for _pid in pids),)
wait_task_desc = lambda gpuid: "等待GPU %d任务" % (gpuid,)
