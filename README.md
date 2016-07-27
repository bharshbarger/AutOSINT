# AutOSINT
Tool to automate common osint tasks

A project to try to automate some common things checked during open source intelligence gathering engagements.

Right now it can do name lookups via -n, whois via -w Google search for 'password' with 'site:<ip or domain>' and Shodan which currently requires an API key to function properly.


usage: AutOSINT.py [-h] [-d DOMAIN [DOMAIN ...]]
                   [-i IPADDRESS [IPADDRESS ...]] [-a] [-w] [-n] [-g]
                   [-s [SHODAN]] [-v]

