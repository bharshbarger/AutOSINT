#!/usr/bin/env python

import subprocess

class Whois:

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
			#append lists together
			whoisResult.append(whoisCmd)

			#write the file
			for r in whoisResult:
				whoisFile.writelines('\n'.join(r))
			
			#verbosity logic
			if args.verbose is True:
				for w in whoisResult: print '\n'.join(w)

		return whoisResult



def main():
	runWhois=Whois()
	runWhois.run()


if __name__ == '__main__':

    main()