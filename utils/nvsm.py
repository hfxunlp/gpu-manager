#encoding: utf-8

from subprocess import run

def get_gpu_pids(*gpuids, timeout=1.0):

	try:
		p = run(["nvidia-smi", "-q", "-d", "PIDS", "-i", ",".join(str(gpuid) for gpuid in gpuids)], capture_output=True, timeout=timeout)
		tmp = (p.stdout + p.stderr).decode("utf-8").split("\n")
		rs = []
		for tmpu in tmp:
			if tmpu:
				_t = tmpu.strip()
				if _t:
					if _t.find("Process ID") >= 0:
						rs.append(int(_t.split()[-1]))
		return rs
	except Exception as e:
		return []
