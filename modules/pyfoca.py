#!/usr/bin/env python
#https://github.com/altjx/ipwn

import re
import subprocess

class Pyfoca():
    """class to run pyfoca on supplied domain"""
    def __init__(self):
        #init lists
        self.pyfoca_result = []
        self.ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')

    def run(self, args, lookup, reportDir):

        #based on domain or ip, enumerate with index and value
        for i, l in enumerate(lookup):

            #open file to write to
            pyfocaFile = open(reportDir + l + '/' + l + '_pyfoca.txt','w')

            #run pyfoca with -d domain. should automagically do metadata
            try:
                print('[+] Running pyfoca -d {}'.format(l))
                pyfocaCmd = subprocess.Popen(['pyfoca', '-p 5','-d ', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\r\n')
            except:
                print('[-] Error running pyfoca. Make sure it is in your PATH and you are connected to the Internet')
                self.pyfoca_result.append('Error running pyfoca')
                pyfocaFile.writelines('Error running pyfoca')
                continue

            for a in pyfocaCmd:
                fixed_output = self.ansi_escape.sub('', str(a).strip())
                if args.verbose is True:
                    print(fixed_output)
            
                #append output
                pyfocaFile.writelines(fixed_output)
                self.pyfoca_result.append(fixed_output)

            return self.pyfoca_result
