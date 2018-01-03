import time

__version__ = 'FIR 0.1a'

debug = False

startTime = time.time()

dbFile = ('FIR.sqlite')

msfrpcUser = 'fir'
msfrpcPass = 'P455WORDh3r3'

nmapGenericSettings = '--open -n -Pn -sS -T3'

#portsForScanning_TCP = [22,23,25,53,79,80,137,138,139,389,443,445,636,990,1433,3389,5800,5900,8000,8080]
portsForScanning_TCP = [139,445] # limiting it to this port for initial testing as can just spin up a listening service somewhere

commonUsernames = ["administrator", "admin", "root", "user", "guest"]