# AutOSINT
Tool to automate common osint tasks

A project to try to automate some common things checked during open source intelligence gathering engagements.


usage: AutOSINT.py [-h] [-d DOMAIN [DOMAIN ...]]
                   [-i IPADDRESS [IPADDRESS ...]] [-a] [-w] [-n] [-g]
                   [-s [SHODAN]] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN [DOMAIN ...], --domain DOMAIN [DOMAIN ...]
                        the Domain(s) you want to search
  -i IPADDRESS [IPADDRESS ...], --ipaddress IPADDRESS [IPADDRESS ...]
                        the IP address(es) you want to search
  -a, --all             run All queries
  -w, --whois           query Whois
  -n, --nslookup        Name query DNS
  -g, --google          query Google
  -s [SHODAN], --shodan [SHODAN]
                        query Shodan, optionally provide -s <apikey>
  -v, --verbose         Verbosely everything to stdout, equivalent to -wngs
