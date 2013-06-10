#!/usr/bin/env python3
#-*- coding: UTF-8 -*-

import urllib.request, urllib.error, urllib.parse
import sys
import re
import http.cookiejar
import base64
from urllib.parse import urlparse
from xml.dom.minidom import parse, parseString
import xml.dom.minidom
import array, platform, struct, fcntl, socket
import hashlib
import math

ImportCookie = False
Verbose = True
Protocol = None
cookieJar = None

class colors:
	BLACK = '\033[00;30m'
	DGRAY = '\033[01;30m'
	BROWN = '\033[00;33m'
	BLUE = '\033[00;94m'
	GREEN = '\033[00;92m'
	DGREEN = '\033[01;92m'
	YELLOW = '\033[00;93m'
	DYELLOW = '\033[00;93m'
	ORANGE = '\033[01;31m'
	DRED = '\033[01;91m'
	RED = '\033[00;91m'
	VIOLET = '\033[00;35m'
	ENDC = '\033[0m'
	def disable(self):
		BLACK = ''
		DGRAY = ''
		BROWN = ''
		BLUE = ''
		GREEN = ''
		DGREEN = ''
		YELLOW = ''
		DYELLOW = ''
		ORANGE = ''
		DRED = ''
		RED = ''
		VIOLET = ''
		ENDC = ''


def toNowhere(var, var2=None):
	pass

def cookieOut(val):
	pass

def formatCookie(cook):
	ret = '  '
	attributes = cook[1].split(';')
	content = ''
	for a in attributes:
		if content != '':
			content += ';'

		if a.strip().lower() == 'httponly':
			content += colors.DRED + a + colors.ENDC
		elif a.strip().lower() == 'secure':
			content += colors.DRED + a + colors.ENDC
		else:
			cookieOut(a)
			content += a
	ret += colors.DYELLOW + cook[0] + colors.ENDC + ': ' + content
	return ret

def defaultPrintHeaders(headers, hfilter=None):
	if hfilter != None:
		hfilter = hfilter.lower()
	if type(headers) == type({}):
		h1 = []
		for i in headers.keys():
			if i.lower() == "cookie" and type(headers[i]) ==  type({}):
				for c in headers[i].keys():
					h1.append(("Cookie",c + "=" + headers[i][c]))
			else:
				h1.append((i,headers[i]))
		headers = h1
		
	for i in headers:
		if i[0].lower() == hfilter or hfilter == None:
			if i[0].lower() == 'set-cookie' or i[0].lower() == 'cookie':
				printOut(formatCookie(i))
			else:
				printOut('  ' + colors.DGRAY + i[0] + colors.ENDC + ': ' + str(i[1]) )

printHeaders = defaultPrintHeaders

def defaultPrintRequestOut(method, additional):
	if Verbose:
		s = ''
		if method.strip().upper() == 'GET':
			s += colors.VIOLET + method + colors.ENDC
		elif method.strip().upper() == 'POST':
			s += colors.BLUE + method + colors.ENDC
		else:
			s += colors.BROWN + method + colors.ENDC
		s += ' ' + additional
		sys.stdout.write(str(s) + "\n")
printRequest = defaultPrintRequestOut

def printData(data):
	if Verbose:
		if type(data) == type(b''):
			data = data.decode()
		sys.stdout.write(data)

def defaultPrintAnswerOut(code,additional):
	if Verbose:
		ret = '  '
		if code == 200:
			ret += colors.DGREEN + '200 ' + colors.ENDC
		elif code == 302:
			ret += colors.ORANGE + '302 ' + colors.ENDC
		else:
			ret += colors.DRED + str(code) + colors.ENDC + ' '
		ret += str(additional)
		ret += '\n'
		sys.stdout.write(ret)

printAnswer = defaultPrintAnswerOut

def defaultPrintOut(s):
	if Verbose:
		sys.stdout.write(str(s) + "\n")
		sys.stdout.flush()

printOut = defaultPrintOut

def defaultWriteOut(s):
	if Verbose:
		sys.stdout.write(str(s))

writeOut = defaultWriteOut

def defaultDebug(s):
	if Verbose:
		sys.stdout.write('Debug: ' + str(s) + '\n')

printDebug = defaultDebug

def outputControl(requests = True, headers = False , response = True, misc = False, debug = False):
	if not headers:	
		printHeaders = toNowhere

	if not requests:
		printRequest = toNowhere
	else:
		printRequest = defaultPrintRequestOut
	
	if not response:
		printAnswer = toNowhere
	else:
		printAnswer = defaultPrintAnswerOut
	
	if not misc:
		printOut = toNowhere
	else:
		printOut = defaultPrintOut

	if not debug:
		printDebug = toNowhere
	else:
		printDebug = defaultDebug

	
def headersValue(headerList):
	res = '['
	for i in headerList:
		res += str(i) + ' '
	res = res[:-1] + ']'
	return res

def b64decode(s):
	finals = s

	print((len(s)))
	modres = len(s) % 4
	if  len(re.findall('=',s)) != 0:
		return base64.b64decode(s)
	elif modres == 0:
		return base64.b64decode(s)
	elif modres == 1:
		finals = s + 'w==' 
	elif modres == 2:
		finals = s + '=='
	else:
		finals = s + '='

	print(finals)

	return base64.b64decode(finals)

def all_interfaces():
	SIOCGIFCONF = 0x8912
	MAXBYTES = 8096

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	names = array.array('B', b'\0' * MAXBYTES)
	
	arch = platform.architecture()[0]
	var1 = -1
	var2 = -1
	if arch == '32bit':
	  var1 = 32
	  var2 = 32
	elif arch == '64bit':
	  var1 = 16
	  var2 = 40

	outbytes = struct.unpack('iL', fcntl.ioctl(s.fileno(), SIOCGIFCONF, struct.pack('iL', MAXBYTES, names.buffer_info()[0])))[0]

	namestr = names.tobytes()
	dic = {}
	for i in range(0, outbytes, var2):
		dic[namestr[i:i+var1].decode().split('\0', 1)[0]] = socket.inet_ntoa(namestr[i+20:i+24])
	return dic

def birthdayProblem(space,sampleNumber):
	return 1 - math.exp(-((sampleNumber**2)/(2*space)))

def hexify(val,sep = " ", lblocksize = 0, linesize = 0):
	if type(val) == type(""):
		val = val.encode()
	if linesize != 0 and lblocksize == 0:
		linesize = 0
	
	i = 0
	c = 0
	fi = ""
	while i < len(val):
		if i != 0:
			if lblocksize != 0 and i % lblocksize == 0:
				fi += " "
			if linesize != 0 and i % (lblocksize * linesize) == 0:
				fi += "\n"
		
		fi += "{0:02x}".format(val[i]) + sep
		i += 1

	return fi

def decify(val,printable = False):
	if type(val) == type(""):
		val = val.encode()
	i = 0
	c = 0
	fi = ""
	sep = " "
	if printable:
		sep = "\n"
	while i < len(val):
		if i != 0 and i % 16 == 0:
			fi += sep
		elif i != 0 and i % 8 == 0:
			fi += " "
		fi += "{0:03d} ".format(val[i])
		i += 1

	return fi

def intToBits(integer):
	return str(integer) if integer<=1 else intToBits(integer>>1) + str(integer&1)

def stringToBits(s):
	res = ''
	for c in s:
		res += intToBits(ord(c))
	return res

def charaterSet(string=None,filename=None):
	charSpace=set()
	if filename != None:
		opendFile = open(filename, "r")
		for line in opendFile:
			charSpace = charSpace | set(line.strip())
		opendFile.close()
	elif string != None:
		charSpace = set(string)	
	return list(charSpace)

def decodeASP(text):
	""" base64 decode function for (ASP).NET """
	isbytes = True
	if not isinstance(text, bytes):
		text = text.encode()
		isbytes = False

	try:
		count = int(text[-1:])
		text = text[:-1]
		for i in range(count):
			text += b'='
	except ValueError:
		pass

	text = base64.urlsafe_b64decode(text)

	if isbytes:
		return text
	else:
		return text.decode()

def encodeASP(text):
	""" base64 encode function for (ASP).NET """
	isbytes = True

	if not isinstance(text, bytes):
		text = base64.urlsafe_b64encode(text.encode())
		isbytes = False	
	else:
		text = base64.urlsafe_b64encode(text)
	count = len(re.findall(b'=',text))
	for i in range(count):
		text = text[:-1]
	text = text + str(count).encode()

	if isbytes:
		return text
	else:
		return text.decode()

class SmartRedirectHandler(urllib.request.HTTPRedirectHandler):
	def http_error_301(self, req, fp, code, msg, headers):

		self.preProcessingRedirection(req, fp, code, msg, headers)
		result = super(SmartRedirectHandler, self).http_error_301(req, fp, code, msg, headers)
		self.postProcessingRedirection(result)

		return result
	
	def http_error_302(self, req, fp, code, msg, headers):
		self.preProcessingRedirection(req, fp, code, msg, headers)
		result = super(SmartRedirectHandler, self).http_error_302(req, fp, code, msg, headers)
		self.postProcessingRedirection(result)
		return result

	def preProcessingRedirection(self, req, fp, code, msg, headers):
		location = ''
		for i in headers._headers:
			if i[0] == 'Location':
				location = i[1].strip()
			
		req.add_header('Host',urlparse(location).netloc)

		printAnswer(code, str(msg) + " " + location)
		printHeaders(headers._headers,'Set-Cookie')

	def postProcessingRedirection(self, result):
		printRequest("GET", result.geturl())

def stringToHexCSV(s):
	hexs = s.encode('hex')
	ret = ' '.join(hexs[i:i+2] for i in range(0, len(hexs), 2))
	return ret

def defaultCreateOpener(withCookieJar = True, withBurpProxy = True):
	global cookieJar

	if withCookieJar:
		cookieJar = urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())

	proxy_handler = None	
	if withBurpProxy:
		proxy_handler = urllib.request.ProxyHandler({'https': 'https://127.0.0.1:8080/', 'http': 'http://127.0.0.1:8080/'})
	
	ret = None
	if withCookieJar and withBurpProxy:
		ret = urllib.request.build_opener(proxy_handler, SmartRedirectHandler(), cookieJar)
	elif withCookieJar:
		ret = urllib.request.build_opener(SmartRedirectHandler(), cookieJar)
	elif withBurpProxy:
		ret = urllib.request.build_opener(proxy_handler, SmartRedirectHandler())
	return ret

def processingCookies(headers):
	cookies = headers['Cookie']
	final = ''
	if type(cookies) == type(""):
		return
	for c in cookies.keys():
		final += " " + c + "=" + cookies[c] + ";"
	
	headers['Cookie'] = final

	return headers

createOpener = defaultCreateOpener

def requestC(opener,url, headers, data, method = 'POST'):
	[answer, code] = requestB(opener,url, headers, data, method)
	return answer

def requestB(opener,url, headers, data, method = 'POST'):
	answer = ''
	retcode = None
	additionalInfo = '[None]'
	contentLenght = None

	if ImportCookie:
		headers = processingCookies(headers)
	data = urllib.parse.urlencode(data)

	if method == 'GET':
		if data:
			url = url + '?' + data
		data = None
	elif method == 'POST':
		headers['Content-Length'] = len(data)
		data = data.encode()

	request = urllib.request.Request(url,data,headers)
	try:
		printRequest(request.get_method(), request.get_full_url())
		if data:
			printData(data)
		
		f = opener.open(request)
		
		headers = f.getheaders()
		code = f.code
		retcode = code
		answer = f.read()
		m = hashlib.md5()
		m.update(answer)
		for h in headers:
			if h[0].lower() == 'content-length':
				contentLenght = h[1]
				additionalInfo = '[' + str(h[1]) + ']'

		printAnswer(code,additionalInfo)
		printHeaders(headers,'Set-Cookie')

	except urllib.error.HTTPError as error:
		for h in error.headers:
			if h.lower() == 'content-length':
				printAnswer(str(error.code) , ' [' + str(error.headers[h]) + ']')
		else:
                	printAnswer(str(error.code) , ' [-1]')
		retcode = error.code
		answer = error.read()
	except urllib.error.URLError as error:
		printAnswer(str(error))
	return answer, retcode

def parseBurpData(fileName):
	global Protocol
	url = ''
	host = ''
	data = None
	contentType = 'None'
	headers = {}
	indata = None
	try:
		indata = open(fileName,"r")
	except IOError as error:
		print(str(error))
		sys.exit(1)

	line = indata.readline()
	res = line.partition(' ')
	method = res[0]
	printDebug('method ' + method)
	res = res[2].rpartition(' ')
	uri = res[0]
	printDebug('URI: ' + str(uri))

	if Protocol == None:
		rulo = urlparse(uri)
		printOut('Scheme not given, trying to guess it from burp request.')
		if rulo.scheme != 'http' or rulo.scheme != 'https':
			printOut('** Could not determine the scheme from the HTTP request, please configure one **')
			sys.exit(1)
		else:
			Protocol = rulo.scheme

	line = indata.readline()
	while line.strip():
		res = line.partition(':')
		if res[0] == 'Host':
			host = res[2].strip()
		if res[0] == 'Content-Type':
			contentType = res[2].strip()
		if res[0] == 'Cookie':
			if ImportCookie:
				cookies = res[2].split(';')
				for c in cookies:
					tm = c.strip().partition('=')
					if res[0] not in headers:
						headers[res[0]] = {tm[0]:tm[2]}
					else:
						headers[res[0]][tm[0]] = tm[2]
				line = indata.readline()
				continue
		headers[res[0]] = res[2].strip()
		line = indata.readline()
	
	if method == 'POST':
		url = Protocol + '://' + host + uri
		data = indata.read().strip()

		if len(data) == 0:
			data = None
		else:
			urlencodedcontenttype = re.compile('application\/x-www-form-urlencoded')
			if urlencodedcontenttype.match(contentType):
				data = urllib.parse.parse_qs(data)
				for d in list(data.keys()):
					if len(data[d]) > 1:
						printOut("Multiple value for the same field. Odd... taking the first one")
					data[d] = data[d][0]
			elif contentType == 'text/xml; charset=UTF-8':
				data = parseString(data)
			else:
				printOut('Unknown Content type: ' + str(contentType))		

	elif method == 'GET':
		res = uri.rpartition('?')
		uri = res[0]
		if len(res) == 3:
			if uri == '':
				uri = res[2]
			data = urllib.parse.parse_qs(res[2])
			for d in list(data.keys()):
				if len(data[d]) > 1:
					printOut("Multiple value for the same field. Odd... taking the first one")
				data[d] = data[d][0]
		
		url = Protocol + '://' + host + uri
	
	indata.close()

	return url, headers,data, method

