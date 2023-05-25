# GPU Man(ager)

简单好用的GPU任务管理器

## 安装

需要python版本>=3.6。

以将代码放在`/opt/gpu-manager`为例，推荐通过conda环境管理。

创建conda环境，已环境名`gpuman`，python 3.11为例：`conda create -n gpuman python=3.11`。

激活conda环境：`conda activate gpuman`。

安装`requirements.txt`中的依赖包，通过conda或pip均可（有些包只支持pip）：`pip install -r requirements.txt`。

将创建conda环境用户home目录的.bashrc中初始化conda环境的代码块提取出来，作为`init_conda.sh`，`scripts/init_conda.sh`为例。

将等待任务的脚本复制到代码目录：`cp /opt/gpu-manager/scripts/wait_pid.sh /opt/gpu-manager/`。
将启动脚本复制到代码目录：`cp /opt/gpu-manager/scripts/start_gpuman.sh /opt/gpu-manager/`，并根据代码路径调整其内容(`wkpath`，如果非root启动还需要删除其中的`ionice -c 2 -n 0 nice -n -20 `)。

如开机自启动(需root权限)：

需修改`scripts/gpuman.service`中的安装路径。

将`scripts/gpuman.service`复制到systemd的管理路径：`sudo cp scripts/gpuman.service /etc/systemd/system/`。

更新systemd：`sudo systemctl daemon-reload`。

启用服务：`sudo systemctl enable gpuman.service`。

## 初始化

配置`cnfg.py`：

```
# 网页端口
use_port = 8888
# 管理的GPU ID
use_gpus = list(range(4))
# GPU ID重映射，用于单卡多任务调度，例如{i: i // 2 for i in range(4)}可将0、1映射为0，2、3映射为1。
device_id_map = {}
# 超级密码
admin_passwd = "atestb"
# 任务调度周期
sleep_secs = 1.0
# 状态保存周期
save_every = 900.0

# 缓存页面数
max_caches = 1024
# 达到最大缓存后，缓存清理概率
cache_drop_p = 0.1
# 短期缓存时长(s)
cache_life_short = 60.0
# 中缓存时长
cache_life_medium = 1800.0
# 长缓存时长
cache_life_long = 604800.0
# 过期缓存清理周期
cache_clean_time = 3000.0

# 会话时常
session_life_time = timedelta(days=7)
# 状态和查询页面自动刷新间隔
refresh_time = str(int(save_every))

# root模式，不需要其他用户的密码鉴定即可切换到其他用户执行任务，即便服务以root用户运行，也推荐设定为False
root_mode = False
# 激进的进程清理
aggressive_clean = False

# 保存的服务状态文件
state_file = ".states.pkl"
# 转储已完成任务的文件
done_task_file = "done_tasks.txt"

# 自动转储的转储任务概率
auto_dump_p = 0.8
# 达到多少条任务后自动转储
auto_dump_thres = 100
# 最大任务ID（达到后从1重新开始）
round_tid = None

# 哈希的密码长度
digest_size = 64
# 用于保护哈希函数的密钥
hash_wd = admin_passwd
# 会话管理的密钥长度
secret_key_length = digest_size

# 用户列表页面每行的用户数
num_user_line = 10

# 页面压缩级别
flask_compress_level = 6

# 邮件服务的主机，端口，用户名，密码和邮件主题
smtp_host = "smtp.qq.com"
smtp_port = 465
smtp_user = "test@foxmail.com"
smtp_passwd = None
smtp_subject = "服务器通知"

# 默认的任务配置
default_task = {"wkd": "", "cmd": "bash task.sh", "stdout": "stdout.txt", "stderr": "stderr.txt", "ngpu": "1", "force_gpuids": "None", "real_gpuid_args": "None", "timeout": "None", "email": "", "desc": ""}

# 当管理的GPU被其它进程使用时，创建等待该进程的任务
# 等待任务的工作路径
wait_task_wkd = "/opt/gpu-manager"
# 等待任务的执行命令生成函数，入参：进程的PID(s)
wait_task_cmd = lambda pids: "bash %s/wait_pid.sh %s" % (wait_task_wkd, " ".join(str(_pid) for _pid in pids),)
# 等待任务的任务描述生成函数，入参GPU ID
wait_task_desc = lambda gpuid: "等待GPU %d任务" % (gpuid,)
```

激活conda环境后，启动服务：`python server.py`(如配置为systemd的服务，可通过：`sudo systemctl start gpuman.service`启动)。

访问`http://服务器IP:端口/admin`进入管理页面，输入超级密码，执行`useradd 用户名 密码`命令，创建第一个用户，再执行`suadd 用户名`命令，将该用户设为管理员。然后即可访问`http://服务器IP:端口`登录使用。

存在管理员用户时，可在管理页面执行`set ctx.enable_super_passwd False`禁用超级密码，防止暴力破解超级密码取得管理权限。

## 重置

删除代码目录下的`done_tasks.txt`和`.states.pkl.*`文件：`rm done_tasks.txt .states.pkl.*`。

## 管理命令

`useradd user [passwd serv_usr serv_passwd]`：创建用户`user`，密码为`passwd`，对应的服务器系统帐号密码为`serv_usr`和`serv_passwd`。后三个参数默认值同`user`，可登录后自行修改。

`addusers a b c ...`：创建一批用户`a b c ...`，密码同用户名。

`userdel a b c ...`：删除用户`a b c ...`。

`suadd a b c ...`：将`a b c ...`设为管理员。

`sudel a b c ...`：取消`a b c ...`管理员身份。

`lockuser a b c ...`：禁止`a b c ...`登录。

`unlockuser a b c ...`：允许`a b c ...`登录。

`stop`：停止调度服务。

`force stop`：强制停止调度服务。

`start`：开始调度服务（只在`stop`后重新开始时使用）。

`exit`：退出服务（正在运行的任务继续运行）。

`force exit`：退出服务（正在运行的任务停止）。

`dump k(all)`：转储状态页面的前`k`个/所有已完成任务。

`dumpuser a k(all)`：转储用户`a`的前`k`个/所有已完成任务。

`dumptask i j k ...`：转储任务ID为`i j k ...`的任务。

`save state`：保存状态。

`load state`：加载状态。

`save iter k`：设置状态自动保存周期。

`move tid p`：将等待运行且ID为`tid`的任务移动到等待队列的第`p`个。

`add device i j k ...`：增加管理的GPU ID`i j k ...`。

`remove device i j k ...`：不再管理的GPU`i j k ...`。

`set key value`：将`manager`的`key`对象设置为`value`。

`schedule fifo/balance`：设置任务调度方式为`fifo`或`balance`。`fifo`先创建先运行，`balance`优先运行使用GPU少的用户先创建的任务。推荐`balance`，避免在一个用户连续创建大量任务时，出现单用户GPU占用过多，阻塞其他用户使用服务器的情况。

`reschedule`：重新调度，当调度结果和算法预期不同时使用，通常不需要使用。

`prompt xxx`：设置提示信息为`xxx`，`None`取消提示信息。

`clear cache`：清空页面缓存，当页面显示和实际状态不一致时使用，通常不需要使用。

`lock/unlock lock_name`：锁/解锁`manager`的锁对象`lock_name`，通常不应使用。

## 创建任务

用户创建的训练任务中也需要初始化其conda/virtualenv环境，用户创建类似`init_conda.sh`的脚本后，可参考下面`task.sh`的例子配置任务脚本：

```
#!/bin/bash

set -e -o pipefail -x

# 初始化user的conda环境
source /home/user/init_conda.sh

# 激活任务使用的环境xxx
conda activate xxx

# 运行train.py，将task.sh的参数传给train.py
python train.py $@
```
然后将`bash task.sh`配置为任务的执行命令。

## 性能

Python 3.11.0，Intel Core M3-7Y30 CPU，视不同的请求类型，每秒可处理约300-550请求(由`test/pressure.py`测得)。

## 其它说明

通过`CUDA_VISIBLE_DEVICES`和`NVIDIA_VISIBLE_DEVICES`配置任务的GPU，所以任务执行的脚本和程序中不应该修改这两个环境变量，否则会使用其它可能正在使用的GPU，导致分配的GPU没有得到使用，遇到显存不足等错误。

任务的工作路径应使用绝对路径，执行任务前会自动切换到任务配置的工作路径，所以任务脚本中不需要再通过`cd`命令切换到配置的工作路径。

用户优先级一般大于0，默认为1，越大优先级越高，当优先级为`k`的用户使用`j`块GPU时，调度程序认为用户使用`j/k`块GPU。`0`具有比正值更高的优先级，负值具有最高优先级，当优先级为负值的用户有等待执行的任务时，一般不会启动其他用户的任务。

`cnfg.py`中的`hash_wd`涉及用户密码哈希的计算，修改会导致所有用户密码哈希值的改变，并导致认证/登录失败。此文件一定要只有管理员/root可读写(建议权限700)，避免泄漏超级密码。

`cli.py`可在无法通过网页访问时，使用命令行界面完成交互。同时也展示了json接口的调用方法，可支撑界面的二次开发。

`requirements.txt`为开发使用的库版本，来自conda-forge，低版本的库可能也可运行。
