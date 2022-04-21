#encoding: utf-8

def is_alive(p):

	try:
		return (p.exitcode is None) and p.is_alive()
	except Exception as e:
		return False

def join(p):

	try:
		p.join()
	except Exception as e:
		pass
