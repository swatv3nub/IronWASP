include IronWASP

def start_log_range(req, res)
	GlobalStore.put("log_start_rb_api", Config.last_proxy_log_id + 1)
	res.body_string = "OK"
end
	
start_log_range_l = lambda{|req, res| start_log_range(req, res)}
ApiCallHandler.add_handler("/rb/log_range_start", start_log_range_l)
	
def end_log_range(req, res)
	GlobalStore.put("log_end_rb_api", Config.last_proxy_log_id)
	res.body_string = "OK"
end

end_log_range_l = lambda{|req, res| end_log_range(req, res)}
ApiCallHandler.add_handler("/rb/log_range_end", end_log_range_l)
	
def scan_log_range(req, res)
	start_id = GlobalStore.get("log_start_rb_api")
	end_id = GlobalStore.get("log_end_rb_api")
	(start_id..end_id).each do |i|
		r = Request.from_proxy_log(i)
		s = Scanner.new(r)
		if r.query.count > 0 or r.body.count > 0
			s.inject_query
			s.inject_body
			s.check_all
			s.launch_scan
		end
	end
	res.body_string = "OK"
end

scan_log_range_l = lambda{|req, res| scan_log_range(req, res)}
ApiCallHandler.add_handler("/rb/scan_log_range", scan_log_range_l)
