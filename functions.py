class FastInitialRecon:
    #python3 modules
    import settings
    import os

    import sys
    import nmap
    import sqlite3
    import string
    from texttable import Texttable
    from sqlite3 import Error
    import msfrpc
    from netaddr import IPNetwork
    from time import sleep
    import psutil

    #custom modules
    import definitions

    def __init__(self, targetNetwork):

        # init MSF
        if self.checkMSFRPCrunning() == False:
            print("MSFRPC was not found on local port 55553, attempting to start it")
            self.os.system("msfrpcd -U "+self.settings.msfrpcUser+" -P "+self.settings.msfrpcPass+" --ssl")
            self.sleep(10)
            if self.checkMSFRPCrunning() == False:
                print("Unable to start MSFRPC - exiting")
                self.sys.exit(-1)
            else:
                print("MSFRPC has started")
        elif (self.settings.debug):
            print("MSFRPC was found running")
        msfClient = self.msfrpc.MsfRpcClient(self.settings.msfrpcPass, username=self.settings.msfrpcUser)
        msfConsole = self.msfrpc.MsfConsole(msfClient)
        self.executeMSFcommand(msfConsole, 'color false')
        # / init MSF
        # init database
        try:
            self.os.remove(self.settings.dbFile)
        except OSError:
            pass
        self.databaseTransaction("CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT)")
        self.databaseTransaction("CREATE TABLE openPorts (id INTEGER PRIMARY KEY, hostID INTEGER, portNum INTEGER, TCP INTEGER, FOREIGN KEY (hostID) REFERENCES hosts(id))")
        self.databaseTransaction("CREATE TABLE findings (id INTEGER PRIMARY KEY, openPortID INTEGER, finding TEXT, FOREIGN KEY (openPortID) REFERENCES openPorts(id))")
        for hostAddr in self.IPNetwork(targetNetwork):
            self.databaseTransaction("INSERT INTO hosts (host) VALUES(?)", (str(hostAddr),))
        # / init database

    def checkMSFRPCrunning(self):
        msfRPCRunning = False
        for socket in self.psutil.net_connections():
            if socket.laddr[1] == 55553:
                msfRPCRunning = True
        return msfRPCRunning

    def databaseTransaction(self, query, params=False):
        try:
            db = self.sqlite3.connect(self.settings.dbFile)
            cursor = db.cursor()
            if params != False:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            db.commit()
            result = cursor.fetchall()
            db.close()
            return result
        except self.sqlite3.Error as e:
            print(e)

    def portScan_TCP(self, targetNetwork, targetPort, nmapGenericSettings):
        nm = self.nmap.PortScanner()
        nm.scan(targetNetwork, targetPort, nmapGenericSettings)
        for IP in nm.all_hosts():
            if self.settings.debug:
                print("TCP Port "+targetPort+" found open on host " + IP)
            hostIDResult = self.databaseTransaction("SELECT id FROM hosts WHERE host=?", (str(IP),))
            hostID = hostIDResult[0][0]
            self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, TCP) VALUES(?, ?, 1)", (hostID, targetPort))

    def getDiscoveredOpenPorts(self):
        results = self.databaseTransaction("SELECT hosts.host as IP, openPorts.portNum as Port, openPorts.TCP FROM hosts, openPorts WHERE hosts.id=openPorts.hostID ORDER BY hosts.host, openPorts.portNum")
        return results

    def printDiscoveredOpenPorts(self):
        results = self.getDiscoveredOpenPorts()
        discoveredOpenPortsTable = self.Texttable()
        discoveredOpenPortsTable.add_row(['IP', 'Port Number', 'TCP/UDP'])
        for result in results:
            if (result[2]):
                discoveredOpenPortsTable.add_row([result[0], str(result[1]), 'TCP'])
            else:
                discoveredOpenPortsTable.add_row([result[0], str(result[1]), 'UDP'])
        print(discoveredOpenPortsTable.draw() + "\n")

    def executeMSFcommand(self, msfConsole, msfCommand, printOutput=False):
        msfConsole.write(msfCommand)
        msfReady = False
        while (not msfReady):
            msfResult = msfConsole.read()
            if (not msfResult['busy']):
                msfReady = True
        if (printOutput):
            # The below filter / lambda functions are required to filter out unicode chars, as the "color false" doesn't apply properly
            print(filter(lambda x: x in self.string.printable, msfResult['data']))
            #print(filter(lambda x: x in self.string.printable, msfResult['prompt']))
        else:
            return msfResult

    def smbVersionScan(self):
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smb/smb_version')
        targets = self.databaseTransaction("SELECT DISTINCT hosts.host as IP FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139)AND openPorts.TCP = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS '+host[0]+'/32')
            self.executeMSFcommand(self.msfConsole, 'run', True)