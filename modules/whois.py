#!/usr/bin/env python


import subprocess

class Whois():


	def run(self, args, lookup, reportDir):


		whoisResult=[]

		#iterate the index and values of the lookup list
		for i, l in enumerate(lookup):
			print '[+] Performing whois query ' + str(i + 1) + ' for ' + l
			
			whoisFile=open(reportDir+l+'/'+l+'_whois.txt','w')

			#subprocess open the whois command for current value of "l" in lookup list. 
			#split into newlines instead of commas
			try:
				whoisCmd = subprocess.Popen(['whois',l], stdout = subprocess.PIPE).communicate()[0].split('\n')
			except:
				print '[-] Error running whois command'
				whoisResult.append('Error running whois command')
				continue

			#filter on colon to remove boilerplace. sketchy but an improvement
			for line in whoisCmd:
				if ':' in line:
					whoisResult.append(line)

			#write the file
			for r in whoisResult:
				whoisFile.writelines('\n'.join(r))
			
			#verbosity logic
			if args.verbose is True:
				for w in whoisResult: print ''.join(w)

		return whoisResult