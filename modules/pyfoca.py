#!/usr/bin/env python
#https://github.com/altjx/ipwn

import subprocess

class Pyfoca():

	def run(self, args, lookup, reportDir):
		
		if args.foca is True:
			
			#init lists
			pyfocaResult=[]

			#based on domain or ip, enumerate with index and value
			for i, l in enumerate(lookup):

				#open file to write to
				pyfocaFile=open(reportDir+l+'/'+l+'_pyfoca.txt','w')

				#run pyfoca with -d domain. should automagically do metadata
				try:
					print '[+] Running pyfoca -d %s' % l
					pyfocaCmd = subprocess.Popen(['pyfoca', '-d', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\r\n')
				except:
					print '[-] Error running pyfoca. Make sure it is in your PATH and you are connected to the Internet'
					pyfocaResult.append('Error running pyfoca')
					pyfocaFile.writelines('Error running pyfoca')
					continue
				
				#append output
				pyfocaFile.writelines(pyfocaCmd)
				pyfocaResult.append(pyfocaCmd)
				
				#spew if verbose
				if args.verbose is True: 
					for p in pyfocaResult:print '\n'.join(p)

				return pyfocaResult