from IronWASP import *

def start_log_range(req, res):
	GlobalStore.Put("log_start_py_api", Config.LastProxyLogId + 1)
	res.BodyString = "OK"
	
ApiCallHandler.AddHandler("/py/log_range_start", start_log_range)
	
def end_log_range(req, res):
	GlobalStore.Put("log_end_py_api", Config.LastProxyLogId)
	res.BodyString = "OK"

ApiCallHandler.AddHandler("/py/log_range_end", end_log_range)
	
def scan_log_range(req, res):
	start_id = GlobalStore.Get("log_start_py_api")
	end_id = GlobalStore.Get("log_end_py_api")
	for i in range(start_id, end_id + 1):
		r = Request.FromProxyLog(i)
		s = Scanner(r)
		if r.Query.Count > 0 or r.Body.Count > 0:
			s.InjectQuery()
			s.InjectBody()
			s.CheckAll()
			s.LaunchScan()
	res.BodyString = "OK"

ApiCallHandler.AddHandler("/py/scan_log_range", scan_log_range)


def connection_check(req, res):
	res.BodyString = "OK"

ApiCallHandler.AddHandler("connection_check", connection_check)

def passpharse_check(req, res):
	res.BodyString = "OK"

ApiCallHandler.AddHandler("passpharse_check", connection_check)
