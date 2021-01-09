from System.Net.NetworkInformation import Ping

class PingCheck():
	def __init__(self,ipaddress,activeid, isap):
		self.ipadd = ipaddress
		self.activeid = activeid
		self.isap = isap
		
	def ping(self):
		ipaddress = self.ipadd
		self.isap.print_out("connecting to :  "+ipaddress, 0)
		ping = Ping()
		try:
			pingres = ping.Send(ipaddress)
			status = pingres.Status.ToString()
			if status == 'Success':
				rest = [self.activeid, pingres.Address.ToString(), status,pingres.Options.Ttl]
			else:
				rest = [self.activeid, "", status,0]
			return rest
		except:
			self.isap.print_out(ipaddress + " is not reachable", 0)
			#self.isap.print_out(str(status), 0)
			self.isap.stopper()
			
#		if status == "Success":
#			self.isap.print_out(ipaddress+" is Alive ...", 0)
#			rest = [self.activeid,pingres.Address.ToString(),status,pingres.Options.Ttl]
#			return rest
#		else:
#			self.isap.print_out("Host Down", 0)
#			rest = [self.activeid,ipaddress,status,"Host Down"]
#			isap.stopper()
			#return rest
		
		
		
		