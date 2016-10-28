# AutOSINT
Tool to automate common osint tasks. Probably best run on Kali.

A project to try to automate some common things checked during open source intelligence gathering engagements.

Dependencies: git, python-docx, python shodan, python google, python dns
Installation:

$ git clone https://github.com/bharshbarger/AutOSINT.git

$ chmod +x AutOSINT.py

$ pip install --upgrade pip (optional)

(if missing modules:)

$ sudo apt install python-dns




usage: AutOSINT.py [-h] [-d DOMAIN [DOMAIN ...]]

                   [-i IPADDRESS [IPADDRESS ...]] [-a] [-w] [-n] [-g]
                   
                   [-s [SHODAN]] [-v] [-p] [-t] [-c] [-f]

optional arguments:

  -h, --help            show this help message and exit
  
  -d DOMAIN [DOMAIN ...], --domain DOMAIN [DOMAIN ...]
  
                        the Domain(s) you want to search
                        
  -i IPADDRESS [IPADDRESS ...], --ipaddress IPADDRESS [IPADDRESS ...]
  
                        the IP address(es) you want to search
                        
  -a, --all             run All queries
  
  -w, --whois           query Whois
  
  -n, --nslookup        Name query DNS
  
  -g, --google          query Google for passwords
  
  -s [SHODAN], --shodan [SHODAN]
  
                        query Shodan, optionally provide -s <apikey>
                        
  -v, --verbose         Verbose
  
  -p, --pastebinsearch  Search pastebin
  
  -t, --theharvester    Invoke theHarvester
  
  -c, --creds           Search local copies of credential dumps
  
  -f, --foca            invoke pyfoca
