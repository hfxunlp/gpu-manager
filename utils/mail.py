#encoding: utf-8

import smtplib
from email.message import EmailMessage
from multiprocessing import Process

from utils.fmt.html import build_html_task_table_no_action

SMTP = smtplib.SMTP_SSL

def is_email_address(strin):

	lind = strin.find("@")
	rind = strin.rfind(".")

	return (lind > 0) and (rind > 0) and (rind > lind)

def clean_recp(strin):

	_tmp = "".join([_ for _ in strin.split() if _])
	_tmp = _tmp.replace(";", ",").split(",")

	return [_ for _ in _tmp if is_email_address(_)]

def send_email(tgt, subject, content, host="smtp.qq.com", port=465, user="test@foxmail.com", passwd=None):

	_tgt = clean_recp(tgt)
	if _tgt:
		msg = EmailMessage()
		msg["Subject"] = subject
		msg["From"] = user
		msg["To"] = ", ".join(_tgt)
		msg.set_content("<html>\n<head></head>\n<body>\n%s</body>\n</html>\n" % (content,), subtype="html")

		try:
			with SMTP(host=host, port=port) as smtp:
				if (passwd is not None) and passwd:
					smtp.login(user, passwd)
				smtp.send_message(msg)
		except Exception as e:
			pass

def send_mail_task(subject, task, note=None, host="smtp.qq.com", port=465, user="test@foxmail.com", passwd=None):

	_text = build_html_task_table_no_action(content=[task])
	if note is not None:
		_text = "<p>%s</p>\n%s" % (note, _text,)
	send_email(task.email, subject, _text, host=host, port=port, user=user, passwd=passwd)

def send_mail_task_bg(subject, task, note=None, host="smtp.qq.com", port=465, user="test@foxmail.com", passwd=None):

	p = Process(target=send_mail_task, args=(subject, task,), kwargs={"note":note, "host": host, "port": port, "user": user, "passwd": passwd})
	p.start()

	return p
