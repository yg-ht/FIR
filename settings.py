import time

__version__ = 'FIR 0.1a'

startTime = time.time()

dbFile = ('FIR.sqlite')

nmapGenericSettings = '--open -n -Pn -sS -T3'

#portsForScanning_TCP = [22,23,25,53,79,80,137,138,139,389,443,445,636,990,1433,3389,5800,5900,8000,8080]
portsForScanning_TCP = [8000] # limiting it to this port for initial testing as can just spin up a listening python SimpleHTTPServer on port 8000

commonUsernames = ["administrator", "admin", "root", "user"]