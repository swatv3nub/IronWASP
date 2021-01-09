﻿from IronWASP import *
import db as db2

class portscan:
	def __init__(self,ip,actid, isap):
		self.portscanlist = {"JMS":"50010, 50110, 50210, 50310, 50410, 50510, 50610, 50710, 50810, 50910, 51010, 51110, 51210, 51310, 51410, 51510, 51610, 51710, 51810, 51910, 52010, 52110, 52210, 52310, 52410, 52510, 52610, 52710, 52810, 52910, 53010, 53110, 53210, 53310, 53410, 53510, 53610, 53710, 53810, 53910, 54010, 54110, 54210, 54310, 54410, 54510, 54610, 54710, 54810, 54910, 55010, 55110, 55210, 55310, 55410, 55510, 55610, 55710, 55810, 55910, 56010, 56110, 56210, 56310, 56410, 56510, 56610, 56710, 56810, 56910, 57010, 57110, 57210, 57310, 57410, 57510, 57610, 57710, 57810, 57910, 58010, 58110, 58210, 58310, 58410, 58510, 58610, 58710, 58810, 58910, 59010, 59110, 59210, 59310, 59410, 59510, 59610, 59710, 59810, 59910","TELNET":"50008, 50108, 50208, 50308, 50408, 50508, 50608, 50708, 50808, 50908, 51008, 51108, 51208, 51308, 51408, 51508, 51608, 51708, 51808, 51908, 52008, 52108, 52208, 52308, 52408, 52508, 52608, 52708, 52808, 52908, 53008, 53108, 53208, 53308, 53408, 53508, 53608, 53708, 53808, 53908, 54008, 54108, 54208, 54308, 54408, 54508, 54608, 54708, 54808, 54908, 55008, 55108, 55208, 55308, 55408, 55508, 55608, 55708, 55808, 55908, 56008, 56108, 56208, 56308, 56408, 56508, 56608, 56708, 56808, 56908, 57008, 57108, 57208, 57308, 57408, 57508, 57608, 57708, 57808, 57908, 58008, 58108, 58208, 58308, 58408, 58508, 58608, 58708, 58808, 58908, 59008, 59108, 59208, 59308, 59408, 59508, 59608, 59708, 59808, 59908","IIOP":"50007, 50107, 50207, 50307, 50407, 50507, 50607, 50707, 50807, 50907, 51007, 51107, 51207, 51307, 51407, 51507, 51607, 51707, 51807, 51907, 52007, 52107, 52207, 52307, 52407, 52507, 52607, 52707, 52807, 52907, 53007, 53107, 53207, 53307, 53407, 53507, 53607, 53707, 53807, 53907, 54007, 54107, 54207, 54307, 54407, 54507, 54607, 54707, 54807, 54907, 55007, 55107, 55207, 55307, 55407, 55507, 55607, 55707, 55807, 55907, 56007, 56107, 56207, 56307, 56407, 56507, 56607, 56707, 56807, 56907, 57007, 57107, 57207, 57307, 57407, 57507, 57607, 57707, 57807, 57907, 58007, 58107, 58207, 58307, 58407, 58507, 58607, 58707, 58807, 58907, 59007, 59107, 59207, 59307, 59407, 59507, 59607, 59707, 59807, 59907","P4 over SSL":"50006, 50106, 50206, 50306, 50406, 50506, 50606, 50706, 50806, 50906, 51006, 51106, 51206, 51306, 51406, 51506, 51606, 51706, 51806, 51906, 52006, 52106, 52206, 52306, 52406, 52506, 52606, 52706, 52806, 52906, 53006, 53106, 53206, 53306, 53406, 53506, 53606, 53706, 53806, 53906, 54006, 54106, 54206, 54306, 54406, 54506, 54606, 54706, 54806, 54906, 55006, 55106, 55206, 55306, 55406, 55506, 55606, 55706, 55806, 55906, 56006, 56106, 56206, 56306, 56406, 56506, 56606, 56706, 56806, 56906, 57006, 57106, 57206, 57306, 57406, 57506, 57606, 57706, 57806, 57906, 58006, 58106, 58206, 58306, 58406, 58506, 58606, 58706, 58806, 58906, 59006, 59106, 59206, 59306, 59406, 59506, 59606, 59706, 59806, 59906","P4":"50004, 50104, 50204, 50304, 50404, 50504, 50604, 50704, 50804, 50904, 51004, 51104, 51204, 51304, 51404, 51504, 51604, 51704, 51804, 51904, 52004, 52104, 52204, 52304, 52404, 52504, 52604, 52704, 52804, 52904, 53004, 53104, 53204, 53304, 53404, 53504, 53604, 53704, 53804, 53904, 54004, 54104, 54204, 54304, 54404, 54504, 54604, 54704, 54804, 54904, 55004, 55104, 55204, 55304, 55404, 55504, 55604, 55704, 55804, 55904, 56004, 56104, 56204, 56304, 56404, 56504, 56604, 56704, 56804, 56904, 57004, 57104, 57204, 57304, 57404, 57504, 57604, 57704, 57804, 57904, 58004, 58104, 58204, 58304, 58404, 58504, 58604, 58704, 58804, 58904, 59004, 59104, 59204, 59304, 59404, 59504, 59604, 59704, 59804, 59904","IIOP-SSL":"50003, 50103, 50203, 50303, 50403, 50503, 50603, 50703, 50803, 50903, 51003, 51103, 51203, 51303, 51403, 51503, 51603, 51703, 51803, 51903, 52003, 52103, 52203, 52303, 52403, 52503, 52603, 52703, 52803, 52903, 53003, 53103, 53203, 53303, 53403, 53503, 53603, 53703, 53803, 53903, 54003, 54103, 54203, 54303, 54403, 54503, 54603, 54703, 54803, 54903, 55003, 55103, 55203, 55303, 55403, 55503, 55603, 55703, 55803, 55903, 56003, 56103, 56203, 56303, 56403, 56503, 56603, 56703, 56803, 56903, 57003, 57103, 57203, 57303, 57403, 57503, 57603, 57703, 57803, 57903, 58003, 58103, 58203, 58303, 58403, 58503, 58603, 58703, 58803, 58903, 59003, 59103, 59203, 59303, 59403, 59503, 59603, 59703, 59803, 59903","IIOP Initial Context":"50002, 50102, 50202, 50302, 50402, 50502, 50602, 50702, 50802, 50902, 51002, 51102, 51202, 51302, 51402, 51502, 51602, 51702, 51802, 51902, 52002, 52102, 52202, 52302, 52402, 52502, 52602, 52702, 52802, 52902, 53002, 53102, 53202, 53302, 53402, 53502, 53602, 53702, 53802, 53902, 54002, 54102, 54202, 54302, 54402, 54502, 54602, 54702, 54802, 54902, 55002, 55102, 55202, 55302, 55402, 55502, 55602, 55702, 55802, 55902, 56002, 56102, 56202, 56302, 56402, 56502, 56602, 56702, 56802, 56902, 57002, 57102, 57202, 57302, 57402, 57502, 57602, 57702, 57802, 57902, 58002, 58102, 58202, 58302, 58402, 58502, 58602, 58702, 58802, 58902, 59002, 59102, 59202, 59302, 59402, 59502, 59602, 59702, 59802, 59902","JAVA HTTP":"50000, 50100, 50200, 50300, 50400, 50500, 50600, 50700, 50800, 50900, 51000, 51100, 51200, 51300, 51400, 51500, 51600, 51700, 51800, 51900, 52000, 52100, 52200, 52300, 52400, 52500, 52600, 52700, 52800, 52900, 53000, 53100, 53200, 53300, 53400, 53500, 53600, 53700, 53800, 53900, 54000, 54100, 54200, 54300, 54400, 54500, 54600, 54700, 54800, 54900, 55000, 55100, 55200, 55300, 55400, 55500, 55600, 55700, 55800, 55900, 56000, 56100, 56200, 56300, 56400, 56500, 56600, 56700, 56800, 56900, 57000, 57100, 57200, 57300, 57400, 57500, 57600, 57700, 57800, 57900, 58000, 58100, 58200, 58300, 58400, 58500, 58600, 58700, 58800, 58900, 59000, 59100, 59200, 59300, 59400, 59500, 59600, 59700, 59800, 59900","JAVA HTTPS":"50001, 50101, 50201, 50301, 50401, 50501, 50601, 50701, 50801, 50901, 51001, 51101, 51201, 51301, 51401, 51501, 51601, 51701, 51801, 51901, 52001, 52101, 52201, 52301, 52401, 52501, 52601, 52701, 52801, 52901, 53001, 53101, 53201, 53301, 53401, 53501, 53601, 53701, 53801, 53901, 54001, 54101, 54201, 54301, 54401, 54501, 54601, 54701, 54801, 54901, 55001, 55101, 55201, 55301, 55401, 55501, 55601, 55701, 55801, 55901, 56001, 56101, 56201, 56301, 56401, 56501, 56601, 56701, 56801, 56901, 57001, 57101, 57201, 57301, 57401, 57501, 57601, 57701, 57801, 57901, 58001, 58101, 58201, 58301, 58401, 58501, 58601, 58701, 58801, 58901, 59001, 59101, 59201, 59301, 59401, 59501, 59601, 59701, 59801, 59901","Databse":"1527,1433","Gateway-Secure":"4800-4899","ICM - SMTP":"25","ICM - HTTPS":"44300-44399","Message Server HTPPS":"44400-44499","Dispatcher":"3200-3299","ICM HTTP":"8000-8099","Gateway":"3300-3399","Message Server":"3600-3699","Message Server HTTP":"8100-8199","Start Service":"50013, 50113, 50213, 50313, 50413, 50513, 50613, 50713, 50813, 50913, 51013, 51113, 51213, 51313, 51413, 51513, 51613, 51713, 51813, 51913, 52013, 52113, 52213, 52313, 52413, 52513, 52613, 52713, 52813, 52913, 53013, 53113, 53213, 53313, 53413, 53513, 53613, 53713, 53813, 53913, 54013, 54113, 54213, 54313, 54413, 54513, 54613, 54713, 54813, 54913, 55013, 55113, 55213, 55313, 55413, 55513, 55613, 55713, 55813, 55913, 56013, 56113, 56213, 56313, 56413, 56513, 56613, 56713, 56813, 56913, 57013, 57113, 57213, 57313, 57413, 57513, 57613, 57713, 57813, 57913, 58013, 58113, 58213, 58313, 58413, 58513, 58613, 58713, 58813, 58913, 59013, 59113, 59213, 59313, 59413, 59513, 59613, 59713, 59813, 59913","Secure Start Service":"50014, 50114, 50214, 50314, 50414, 50514, 50614, 50714, 50814, 50914, 51014, 51114, 51214, 51314, 51414, 51514, 51614, 51714, 51814, 51914, 52014, 52114, 52214, 52314, 52414, 52514, 52614, 52714, 52814, 52914, 53014, 53114, 53214, 53314, 53414, 53514, 53614, 53714, 53814, 53914, 54014, 54114, 54214, 54314, 54414, 54514, 54614, 54714, 54814, 54914, 55014, 55114, 55214, 55314, 55414, 55514, 55614, 55714, 55814, 55914, 56014, 56114, 56214, 56314, 56414, 56514, 56614, 56714, 56814, 56914, 57014, 57114, 57214, 57314, 57414, 57514, 57614, 57714, 57814, 57914, 58014, 58114, 58214, 58314, 58414, 58514, 58614, 58714, 58814, 58914, 59014, 59114, 59214, 59314, 59414, 59514, 59614, 59714, 59814, 59914","HTTP Services":"8086",}
		self.dbdict={}
		self.ip = ip
		self.actid = actid
		self.isap = isap
	def controller(self):
		for lin in self.portscanlist.iterkeys():
			ps = PortScanner(self.ip,str(self.portscanlist[lin]),3000)
			res = ps.Scan()
			self.dbdict[lin] = res
		self.dbdict["ip"] = self.ip
		self.dbdict["actid"]= self.actid
		j = IronThread.Run(self.portscanresult)
		
	def portscanresult(self):
		dbw = db2.dbwrite(self.isap)
		dbw.portscanwrite(self.dbdict)