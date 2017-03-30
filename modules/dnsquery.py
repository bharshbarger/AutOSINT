#!/usr/bin/env python


import subprocess

class Dnsquery():



	def run(self, args, lookup, reportDir):
		
		dnsResult=[]

		#iterate the index and values of the lookup list
		for i, l in enumerate(lookup):
			print '[+] Performing DNS query '+ str(i + 1) + ' using "host -a ' + l+'"'
			dnsFile=open(reportDir+l+'/'+l+'_dns.txt','w')
			#subprocess to run host -a on the current value of l in the loop, split into newlines
			try:
				dnsCmd = subprocess.Popen(['host', '-a', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\n')
			except:
				print '[-] Error running dns query'
				dnsResult.append('Error running DNS query')
				continue
			#append lists together
			dnsResult.append(dnsCmd)

			for r in dnsResult:
				dnsFile.writelines('\n'.join(r))

			#print dnsResult if -v
			if args.verbose is True:
				for d in dnsResult: print '\n'.join(d)

		#return list object
		return dnsResult