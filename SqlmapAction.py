from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IContextMenuInvocation
from burp import IHttpRequestResponse
from javax.swing import JMenuItem
import subprocess

pythonfile = "D:\\Program Files\\Python27\\python.exe"

sqlmapapi = "D:\\SecTools\\sqlmapproject-sqlmap-18e62fd\\sqlmap.py"

class BurpExtender(IBurpExtender,  IContextMenuFactory):
	
	def registerExtenderCallbacks(self, callbacks):
		self._actionName = "Sqlmap Scan"
		self._helers = callbacks.getHelpers()
		self._callbacks = callbacks
		callbacks.setExtensionName("Sqlmap Scan")
		callbacks.registerContextMenuFactory(self)
		return 

	def createMenuItems(self, invocation):
		menu = []
		responses = invocation.getSelectedMessages()
		if len(responses) == 1:
			menu.append(JMenuItem(self._actionName, None , actionPerformed= lambda x, inv=invocation: self.sqlMapScan(inv)))
			return menu
		return None

	def sqlMapScan(self, invocation):
		request = invocation.getSelectedMessages().pop()
		analyzedRequest = self._helers.analyzeRequest(request)
		url = analyzedRequest.url
		body = ""
		cookie = ""
		referer = ""
		useragent = ""
		headers = analyzedRequest.getHeaders()
		for header in headers:
			if header.startswith("Cookie: "):
				cookie = header.replace("Cookie: ","")
			elif header.startswith("Referer: "):
				referer = header.replace("Referer: ","")
			elif header.startswith("User-Agent: "):
				useragent = header.replace("User-Agent: ","")
		if analyzedRequest.getMethod() == "POST":
			body = request.getRequest().tostring()[analyzedRequest.getBodyOffset():]

		cmd = "\"%s\" %s -u \"%s\" --data \"%s\" --batch --beep --cookie \"%s\" --user-agent \"%s\" --referer \"%s\" " % (pythonfile, sqlmapapi, url, body, cookie, useragent, referer)
		print cmd
		sqlmapdir = "D:\\SecTools\\sqlmapproject-sqlmap-18e62fd\\"
		sub = subprocess.Popen(cmd, cwd=sqlmapdir, stdout=subprocess.PIPE)


