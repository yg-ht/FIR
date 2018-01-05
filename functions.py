class FastInitialRecon:
    #python modules
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
    import re
    import subprocess
    import readchar

    #custom modules
    import definitions
    import threading

    def __init__(self, targetNetwork):
        # init general stuff (data definitions, and other things)
        print ('Welcome to Fast Initial Recon (' + self.settings.__version__ + ')')
        self.targetNetwork = targetNetwork
        self.referenceData = self.definitions.buildReferenceArrays(self)
        self.menuActions = self.buildMenuActions()
        # / init general stuff

        # init MSF
        if self.checkMSFRPCrunning() == False:
            print("MSFRPC was not found on local port 55553, attempting to start it")
            self.os.system("msfrpcd -U "+self.settings.msfrpcUser+" -P "+self.settings.msfrpcPass+" --ssl")
            print("Pausing for 15 seconds to let MSFRPC start in background properly")
            self.sleep(15)
            if self.checkMSFRPCrunning() == False:
                print("Unable to start MSFRPC - exiting")
                self.sys.exit(-1)
            else:
                print("MSFRPC has started")
        elif (self.settings.debug):
            print("MSFRPC was found running")
        self.msfClient = self.msfrpc.MsfRpcClient(self.settings.msfrpcPass, username=self.settings.msfrpcUser)
        self.msfConsole = self.msfrpc.MsfConsole(self.msfClient)
        self.executeMSFcommand(self.msfConsole, 'color false')
        # / init MSF

        # init database
        try:
            self.os.remove(self.settings.dbFile)
        except OSError:
            pass
        self.databaseTransaction("CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT)")
        self.databaseTransaction("CREATE TABLE openPorts (id INTEGER PRIMARY KEY, hostID INTEGER, portNum INTEGER, portType INTEGER, FOREIGN KEY (hostID) REFERENCES hosts(id))")
        self.databaseTransaction("CREATE TABLE findings (id INTEGER PRIMARY KEY, openPortID INTEGER, dataSource TEXT, finding TEXT, FOREIGN KEY (openPortID) REFERENCES openPorts(id))")
        for hostAddr in self.IPNetwork(self.targetNetwork):
            self.databaseTransaction("INSERT INTO hosts (host) VALUES(?)", (str(hostAddr),))
        # / init database

        ### lets go
        self.printMenu()

### Core functionality ###

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

    def stripUnicode(self, data):
        return(filter(lambda x: x in self.string.printable, data))

    def grep(self, haystack, needle):
        lines = ''
        for line in str.splitlines(haystack):
            if (self.re.search(needle, line, self.re.IGNORECASE)):
                lines = lines + line + "\n"
        if (lines):
            lines = self.re.sub("\n$", '', lines)
        return lines

    def grepv(self, haystack, needle):
        lines = ''
        for line in str.splitlines(haystack):
            if (not self.re.search(needle, line, self.re.IGNORECASE)):
                lines = lines + line + "\n"
        if (lines):
            lines = self.re.sub("\n$", '', lines)
        return lines

    def shutdown(self):
        print ('Quiting threads now...')
        self.sleep(1)
        self.sys.exit(0)

    def clearScreen(self):
        self.os.system('clear')

### Output functionality ###

    def printMenu(self):
        print ('Select your action:')
        print ('  1 - Run default tools')
        print ('  2 - Show discovered ports on all targeted systems')
        print ('  3 - Show findings on all targeted systems')
        print ('  C - Clear screen')
        print ('  Q - Quit')
        print (' >> ')
        choice = self.readchar.readkey()
        self.execMenu(choice[0].upper())

    def execMenu(self, choice):
        if choice == '':
            self.menuActions['main_menu']()
        else:
            try:
                self.clearScreen()
                self.menuActions[choice]()
                self.printMenu()
            except KeyError:
                print "Invalid selection, please try again.\n"
                self.menuActions['main_menu']()

    def buildMenuActions(self):
        menuActions = {
            'main_menu': self.printMenu,
            '1': self.runDefaultTools,                # run default tools
            '2': self.printDiscoveredOpenPorts,       # show discovered ports
            '3': self.printFindings,                  # show findings
            'C': self.clearScreen,                    # clear the screen
            'Q': self.shutdown                        # quit
        }
        return menuActions

    def printDiscoveredOpenPorts(self):
        results = self.getDiscoveredOpenPorts()
        discoveredOpenPortsTable = self.Texttable()
        discoveredOpenPortsTable.header(['IP', 'Port Number', 'Port Type'])
        for result in results:
            if (result[2] == 1):
                discoveredOpenPortsTable.add_row([result[0], str(result[1]), 'TCP'])
            elif (result[2] == 2):
                discoveredOpenPortsTable.add_row([result[0], str(result[1]), 'UDP'])
        print(discoveredOpenPortsTable.draw() + "\n")

    def printFindings(self):
        results = self.getFindings()
        findingsTable = self.Texttable()
        findingsTable.set_cols_width([16, 6, 5, 12, 70])
        findingsTable.header(['IP', 'Port Number', 'Port Type', 'Data Source', 'Finding'])
        for result in results:
            findingsTable.add_row([result[0], str(result[1]), 'TCP', result[3], result[4]])
        print(findingsTable.draw() + "\n")

### secondary functionality ###

    def getHostID(self, hostIP):
        hostID = self.databaseTransaction("SELECT id FROM hosts WHERE host=?", (str(hostIP),))[0][0]
        return hostID

    def getOpenPortID(self, hostIP, portNum, portType):
        hostID = self.getHostID(hostIP)
        openPortIDResult = self.databaseTransaction("SELECT id FROM openPorts WHERE hostID=? AND portNum=? AND portType=?", (str(hostID), portNum, portType))
        if(openPortIDResult):
            return openPortIDResult[0][0]

    def storeFinding(self, hostIP, portNum, portType, dataSource, finding):
        openPortID = self.getOpenPortID(hostIP, portNum, portType)
        self.databaseTransaction("INSERT INTO findings (openPortID, dataSource, finding) VALUES (?, ?, ?)", (openPortID, dataSource, finding))

    def getDiscoveredOpenPorts(self):
        results = self.databaseTransaction("SELECT hosts.host, openPorts.portNum, openPorts.portType FROM hosts, openPorts WHERE hosts.id=openPorts.hostID ORDER BY hosts.host, openPorts.portNum")
        return results

    def getFindings(self):
        results = self.databaseTransaction("SELECT hosts.host, openPorts.portNum, openPorts.portType, findings.dataSource, findings.finding FROM hosts, openPorts, findings WHERE hosts.id=openPorts.hostID AND findings.openPortID = openPorts.id ORDER BY hosts.host, openPorts.portNum")
        return results

### primary functionality ###

    def runDefaultTools(self):
        print('Running default tools')
        self.portScan(self.targetNetwork)
        self.nbtScan()
        self.smbVersionScan()
        self.smbUsersScan()
        self.checkSMBshares()
        self.checkSMBshareAccess()

    def singlePortScan_TCP(self, targetPort, nmapGenericSettings):
        nm = self.nmap.PortScanner()
        nm.scan(self.targetNetwork, targetPort, nmapGenericSettings)
        for hostIP in nm.all_hosts():
            if self.settings.debug:
                print("TCP Port "+targetPort+" found open on host " + hostIP)
            hostID = self.getHostID(hostIP)
            if(self.getOpenPortID(hostIP, targetPort, 1)):
                if (self.settings.debug):
                    print("TCP Port already found, skipping...")
            else:
                self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, portType) VALUES(?, ?, 1)",(hostID, targetPort))

    def singlePortScan_UDP(self, targetPort, nmapGenericSettings):
        nm = self.nmap.PortScanner()
        nm.scan(self.targetNetwork, targetPort, nmapGenericSettings)
        for hostIP in nm.all_hosts():
            if self.settings.debug:
                print("UDP Port "+targetPort+" found open on host " + hostIP)
            hostID = self.getHostID(hostIP)
            if (self.getOpenPortID(hostIP, targetPort, 2)):
                if (self.settings.debug):
                    print("UDP Port already found, skipping...")
            else:
                self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, portType) VALUES(?, ?, 2)",(hostID, targetPort))

    def portScan(self, allPorts=False):
        for targetPort in self.settings.portsForScanning_TCP:
            if self.settings.debug:
                print("Scanning to see if TCP/"+str(targetPort)+" is open on any in-scope IP")
            self.singlePortScan_TCP(str(targetPort), self.settings.nmapGenericSettingsTCP)
        for targetPort in self.settings.portsForScanning_UDP:
            if self.settings.debug:
                print("Scanning to see if UDP/"+str(targetPort)+" is open on any in-scope IP")
            self.singlePortScan_UDP(str(targetPort), self.settings.nmapGenericSettingsUDP)

    def executeMSFcommand(self, msfConsole, msfCommand, printOutput=False):
        msfConsole.write(msfCommand)
        msfReady = False
        msfResult = False
        while (not msfReady):
            msfResult = msfConsole.read()
            if (not msfResult['busy']):
                msfReady = True
        if (printOutput):
            print(self.stripUnicode(msfResult['data']))
            print(self.stripUnicode(msfResult['prompt']))
        else:
            return msfResult

    def smbVersionScan(self):
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smb/smb_version')
        targets = self.databaseTransaction("SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS '+host[0]+'/32')
            msfResult = self.executeMSFcommand(self.msfConsole, 'run')
            try:
                portNum = int(self.grep(msfResult['data'], host[0]).split("Host is running ")[0].split(":")[1].split(" ")[0])
            except IndexError as e:
                print (e)
                print (msfResult['data'])
            msfFinding = self.grep(msfResult['data'], host[0]).split("Host is running ")[1]
            self.storeFinding(host[0],portNum,1,"SMB Version Scan",msfFinding)

    def nbtScan(self):
        targets = self.databaseTransaction(("SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=139 AND openPorts.portType = 1 ORDER BY hosts.host"))
        for host in targets:
            nbtProcess = self.subprocess.Popen(["nbtscan", "-v", "-s ~=~=~", host[0]], stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            nbtScanResult = self.stripUnicode(nbtProcess.communicate()[0])
            for code in self.referenceData['netbiosCodes']:
                netbiosCodeResult = self.grep(nbtScanResult, code[0])
                if (netbiosCodeResult):
                    if (self.re.search('MAC', netbiosCodeResult)):
                        netbiosValue = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[2]
                        netbiosType = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[1]
                    else:
                        netbiosType = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[2]
                        netbiosValue = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[1]
                    self.storeFinding(host[0], 139, 1, 'NBTscan', netbiosType + ": " + netbiosValue)

    def checkSMBshares(self):
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            smbSharesProcess = self.subprocess.Popen(["smbclient", "-N", "-L", host[0]], stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            smbSharesScanResult = self.re.sub('\t', '', self.re.sub(' +',' ',self.grep(self.stripUnicode(smbSharesProcess.communicate()[0]), 'Disk')))
            smbSharesScanResultValue = smbSharesScanResult.split(' ')[0]
            smbSharesScanResultType = smbSharesScanResult.split(' ')[1]
            self.storeFinding(host[0], 445, 1, 'SMB share discovery', 'Non-default share.\nNamed:\t' + smbSharesScanResultValue + '\nType:\t' + smbSharesScanResultType)

    def smbUsersScan(self):
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smb/smb_enumusers')
        targets = self.databaseTransaction("SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS '+host[0]+'/32')
            msfResult = self.executeMSFcommand(self.msfConsole, 'run')
            portNum = int(self.grep(msfResult['data'], host[0]).split(" - ")[0].split(":")[1].split(" ")[0])
            msfFindingDetail = self.grep(msfResult['data'], host[0]).split(" [ ")[1].split(" ]")[0]
            if (msfFindingDetail):
                msfFinding = 'Users found: ' + msfFindingDetail
            else:
                msfFinding = 'No users found on host (probably no permissions)'
            self.storeFinding(host[0],portNum,1,"SMB user discovery",msfFinding)

    def checkSMBshareAccess(self, username = '', password = ''):
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            if (username and password):
                smbSharesProcess = self.subprocess.Popen(["smbmap", "-H", host[0], "-U", username, "-P", password], stdout=self.subprocess.PIPE,stderr=self.subprocess.STDOUT)
            elif (username and not password):
                smbSharesProcess = self.subprocess.Popen(["smbmap", "-H", host[0], "-U", username],stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            else:
                smbSharesProcess = self.subprocess.Popen(["smbmap", "-H", host[0]], stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            smbSharesScanResult = self.re.sub("\n\t", "\n", self.re.sub("^\t", '', self.re.sub(' +',' ',self.grepv(self.grepv(self.grepv(self.stripUnicode(smbSharesProcess.communicate()[0]), host[0]), 'Finding open SMB ports....'), '-----------'))))
            self.storeFinding(host[0], 445, 1, 'SMB share access checker', 'The following share accesses were found:\n' + smbSharesScanResult)