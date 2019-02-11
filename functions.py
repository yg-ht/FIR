class FastInitialRecon:
    # python modules
    import settings
    import os
    import sys
    import nmap
    import sqlite3
    import string
    import msfrpc
    import psutil
    import re
    import subprocess
    import readchar
    from texttable import Texttable
    from sqlite3 import Error
    from netaddr import IPNetwork
    from time import sleep

    # custom modules
    import definitions
    import threading

    def __init__(self, targetNetwork):
        # init general stuff (data definitions, and other things)
        print ('Welcome to Fast Initial Recon (' + self.settings.__version__ + ')')
        self.targetNetwork = targetNetwork
        if self.settings.debug:
            print("Getting Reference Data")
        self.referenceData = self.definitions.buildReferenceArrays(self)
        if self.settings.debug:
            print("Building Menu Construct")
        self.menuActions = self.buildMenuActions()
        # / init general stuff

        # init MSF
        if self.settings.debug:
            print("Checking MSFRPC")
        if not self.checkMSFRPCrunning():
            print("MSFRPC was not found on local port 55553, attempting to start it")
            self.os.system("msfrpcd -U " + self.settings.msfrpcUser + " -P " + self.settings.msfrpcPass + " --ssl")
            print("Pausing for 15 seconds to let MSFRPC start in background properly")
            self.sleep(15)
            if not self.checkMSFRPCrunning():
                print("Unable to start MSFRPC - exiting")
                self.sys.exit(-1)
            else:
                print("MSFRPC has started")
        elif self.settings.debug:
            print("MSFRPC was found running")
        if self.settings.debug:
            print ("Connecting to MSFRPC")
        self.msfClient = self.msfrpc.MsfRpcClient(self.settings.msfrpcPass, username=self.settings.msfrpcUser)
        if self.settings.debug:
            print ("Establishing MSFRPC Console")
        self.msfConsole = self.msfrpc.MsfConsole(self.msfClient)
        if self.settings.debug:
            print ("Setting color to off in MSFRPC for cleaner output")
        self.executeMSFcommand(self.msfConsole, 'color false')
        # / init MSF

        # init database
        choice = ''
        if self.os.path.isfile(self.settings.dbFile):
            print ("Previous session detected.  Would you like to:\ndestroy it and start a (N)ew session, or (C)ontinue with the previous session?")
            while not (choice == 'C' or choice == 'N'):
                choiceRaw = self.readchar.readkey()
                choice = str(choiceRaw).upper()
        if choice == 'N' or choice == '':
            self.initDB()
            self.portScan()
            self.runDefaultTools()
        # / init database

        # ---- lets go ----#
        self.printMainMenu()

    # ---- Core functionality ----#

    def checkMSFRPCrunning(self):
        msfRPCRunning = False
        for socket in self.psutil.net_connections():
            if socket.laddr[1] == 55553:
                msfRPCRunning = True
        return msfRPCRunning

    def clearScreen(self):
        self.os.system('clear')

    def databaseTransaction(self, query, params=False):
        try:
            db = self.sqlite3.connect(self.settings.dbFile)
            cursor = db.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            db.commit()
            result = cursor.fetchall()
            db.close()
            return result
        except self.sqlite3.Error as e:
            print(e)

    def executeMSFcommand(self, msfConsole, msfCommand, printOutput=False):
        msfConsole.write(msfCommand)
        msfReady = False
        msfResult = False
        while not msfReady:
            msfResult = msfConsole.read()
            if not msfResult['busy']:
                msfReady = True
        if printOutput:
            print(self.stripUnicode(msfResult['data']))
            print(self.stripUnicode(msfResult['prompt']))
        else:
            return msfResult

    def stripUnicode(self, data):
        return filter(lambda x: x in self.string.printable, data)

    def grep(self, haystack, needle):
        lines = ''
        for line in str.splitlines(haystack):
            if self.re.search(needle, line, self.re.IGNORECASE):
                lines = lines + line + "\n"
        if lines:
            lines = self.re.sub("\n$", '', lines)
        return lines

    def grepv(self, haystack, needle):
        lines = ''
        for line in str.splitlines(haystack):
            if not self.re.search(needle, line, self.re.IGNORECASE):
                lines = lines + line + "\n"
        if lines:
            lines = self.re.sub("\n$", '', lines)
        return lines

    def shutdown(self):
        print ('Quiting now...')
        self.sys.exit(0)

    # ---- Output functionality ----#

    def buildMenuActions(self):
        menuActions = {
            'main_menu': self.printMainMenu,
            '01': self.runDefaultTools,
            '02': self.printRunMenu,
            '03': self.printDiscoveredOpenPorts,
            '04': self.printFindings,
            '05': self.printDetailsOfTarget,
            '06': self.printDataMenu,
            '07': self.printDetailsFollowingSearch,
            '0C': self.clearScreen,
            '0Q': self.shutdown,
            '10': self.checkRDNSForIP,
            '11': self.nbtScan,
            '12': self.smbVersionScan,
            '13': self.checkDNSForAXFR,
            '14': self.checkDNSForHostname,
            '15': self.checkSNMPForDefaultCommunities,
            '16': self.checkMSSQLDefaultCreds,
            '17': self.checkFingerUsers,
            '18': self.checkSMTPForDomains,
            '19': self.checkSMTPUserEnum,
            '1M': self.printMainMenu,
            '20': self.printCurrentData,
            '21': self.addUsername,
            '22': self.addHostname,
            '23': self.addDomain,
            '24': self.addPassword,
            '2M': self.printMainMenu
        }
        return menuActions

    def execMenu(self, choice):
        if choice == '':
            self.menuActions['main_menu']()
        else:
            try:
                self.clearScreen()
                if self.settings.debug:
                    print("Menu selection: " + choice)
                self.menuActions[choice]()
                self.menuActions['main_menu']()
            except KeyError:
                print "Invalid selection, please try again.\n"
                self.menuActions['main_menu']()

    def printCurrentData(self):
        print ("The following data is currently in the system")
        print ("Usernames:")
        usernameResults = self.databaseTransaction("SELECT username FROM usernames ORDER BY username")
        if usernameResults:
            for username in usernameResults:
                print(" - " + username[0])
        print("\nHostnames:")
        hostnameResults = self.databaseTransaction("SELECT hostname FROM hostnames ORDER BY hostname")
        if hostnameResults:
            for hostname in hostnameResults:
                print(" - " + hostname[0])
        print("\nDomains:")
        domainResults = self.databaseTransaction("SELECT domain FROM domains ORDER BY domain")
        if domainResults:
            for domain in domainResults:
                print(" - " + domain[0])
        print("\n")

    def printDataMenu(self):
        self.printCurrentData()
        print ('Select your action:')
        print ('  1 - Add usernames')
        print ('  2 - Add hostnames')
        print ('  3 - Add domains')
        print ('  4 - Add passwords')
        print ('  M - Main Menu')
        choice = self.readchar.readkey()
        self.execMenu('2' + choice.upper())

    def printDiscoveredOpenPorts(self, target=None):
        results = self.getDiscoveredOpenPorts(target)
        discoveredOpenPortsTable = self.Texttable()
        discoveredOpenPortsTable.header(['IP', 'Port Number', 'Port Type', 'Common Purpose'])
        for result in results:
            if result[2] == 0 and self.settings.debug:
                discoveredOpenPortsTable.add_row(
                    [result[0], str(result[1]), 'Generic', 'None'])
            if result[2] == 1:
                try:
                    discoveredOpenPortsTable.add_row(
                        [result[0], str(result[1]), 'TCP', self.referenceData['commonTCPPortAssignments'][result[1]]])
                except IndexError:
                    discoveredOpenPortsTable.add_row([result[0], str(result[1]), 'TCP', 'No regsitered purpose'])
            elif result[2] == 2:
                try:
                    discoveredOpenPortsTable.add_row(
                        [result[0], str(result[1]), 'UDP', self.referenceData['commonUDPPortAssignments'][result[1]]])
                except IndexError:
                    discoveredOpenPortsTable.add_row([result[0], str(result[1]), 'UDP', 'No regsitered purpose'])
        print(discoveredOpenPortsTable.draw() + "\n")

    def printDetailsFollowingSearch(self):
        searchCriteria = raw_input("Specify search criteria: ")
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts, findings WHERE hosts.id = openPorts.hostID AND openPorts.id = findings.OpenPortID AND LOWER(findings.finding) LIKE '%" + searchCriteria.lower() + "%'")
        print(targets)
        for target in targets:
            try:
                self.printDiscoveredOpenPorts(target[0])
                self.printFindings(target[0])
                print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
            except TypeError:
                continue

    def printDetailsOfTarget(self):
        target = raw_input("Specify target by IP: ")
        self.printDiscoveredOpenPorts(target)
        self.printFindings(target)

    def printFindings(self, target=None):
        results = self.getFindings(target)
        findingsTable = self.Texttable()
        findingsTable.set_cols_width([16, 6, 5, 12, 80])
        findingsTable.header(['IP', 'Port Number', 'Port Type', 'Data Source', 'Finding'])
        try:
            for result in results:
                findingsTable.add_row(
                    [result[0], str(result[1]), str(self.referenceData['portTypes'][result[2]][1]), result[3],
                     result[4]])
        except TypeError:
            pass
        print(findingsTable.draw() + "\n")

    def printMainMenu(self):
        print ('Select your action:')
        print ('  1 - Run default tools')
        print ('  2 - Run ...')
        print ('  3 - Show discovered ports on all targeted systems')
        print ('  4 - Show findings on all targeted systems')
        print ('  5 - Show all details of specified target')
        print ('  6 - Add data (usernames etc)')
        print ('  7 - Findings free-text search')
        print ('  C - Clear Screen')
        print ('  Q - Quit')
        print (' >> ')
        choice = self.readchar.readkey()
        self.execMenu('0' + choice.upper())

    def printRunMenu(self):
        print ('Select your action:')
        print ('  1 - Run NBTScan')
        print ('  2 - Run SMB Version Scanner')
        print ('  3 - Run AXFR checker')
        print ('  4 - Run Hostname in DNS checker')
        print ('  5 - Check SNMP Services For Default Communities')
        print ('  6 - Check for Default MSSQL Creds')
        print ('  7 - Finger service user enumeration')
        print ('  8 - Check for Domain leak in SMTP service')
        print ('  9 - Perform SMTP User Enumeration')
        print ('  0 - Check for IPs in rDNS')
        print ('  M - Main Menu')
        print (' >> ')
        choice = self.readchar.readkey()
        self.execMenu('1' + choice.upper())

    # ---- secondary functionality ----#

    def addDomain(self):
        print ("Add domain")
        print ("Either add a single record and press enter, or, separate multiple records with commas (no spaces)")
        domains = raw_input("Domain(s): ")
        for domain in domains.split(","):
            self.databaseTransaction("INSERT INTO domains (domain) VALUES(?)", (str(domain),))

    def addHostname(self):
        print ("Add hostname")
        print ("Either add a single record and press enter, or, separate multiple records with commas (no spaces)")
        hostnames = raw_input("Hostname(s): ")
        for hostname in hostnames.split(","):
            self.databaseTransaction("INSERT INTO hostnames (hostname) VALUES(?)", (str(hostname),))

    def addUsername(self):
        print ("Add username")
        print ("Either add a single record and press enter, or, separate multiple records with commas (no spaces)")
        usernames = raw_input("Username(s): ")
        for username in usernames.split(","):
            self.databaseTransaction("INSERT INTO usernames (username) VALUES(?)", (str(username),))

    def addPassword(self):
        print ("Add password")
        print ("Either add a single record and press enter, or, separate multiple records with commas (no spaces)")
        passwords = raw_input("Password(s): ")
        for password in passwords.split(","):
            self.databaseTransaction("INSERT INTO passwords (password) VALUES(?)", (str(password),))

    def getDiscoveredOpenPorts(self, target=None):
        if target:
            results = self.databaseTransaction(
                "SELECT hosts.host, openPorts.portNum, openPorts.portType FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND hosts.host = ? ORDER BY hosts.host, openPorts.portNum",
                (target,))
        else:
            results = self.databaseTransaction(
                "SELECT hosts.host, openPorts.portNum, openPorts.portType FROM hosts, openPorts WHERE hosts.id=openPorts.hostID ORDER BY hosts.host, openPorts.portNum")
        return results

    def getFindings(self, target=None):
        if target:
            results = self.databaseTransaction(
                "SELECT hosts.host, openPorts.portNum, openPorts.portType, findings.dataSource, findings.finding FROM hosts, openPorts, findings WHERE hosts.id=openPorts.hostID AND findings.openPortID = openPorts.id AND hosts.host = ? ORDER BY hosts.host, openPorts.portNum",
                (target,))
        else:
            results = self.databaseTransaction(
                "SELECT hosts.host, openPorts.portNum, openPorts.portType, findings.dataSource, findings.finding FROM hosts, openPorts, findings WHERE hosts.id=openPorts.hostID AND findings.openPortID = openPorts.id ORDER BY hosts.host, openPorts.portNum")
        return results

    def getHostID(self, hostIP):
        hostID = self.databaseTransaction("SELECT id FROM hosts WHERE host=?", (str(hostIP),))[0][0]
        return hostID

    def getOpenPortID(self, hostIP, portNum, portType):
        hostID = self.getHostID(hostIP)
        openPortIDResult = self.databaseTransaction(
            "SELECT id FROM openPorts WHERE hostID=? AND portNum=? AND portType=?", (str(hostID), portNum, portType))
        if openPortIDResult:
            return openPortIDResult[0][0]

    def initDB(self):
        try:
            self.os.remove(self.settings.dbFile)
        except OSError:
            pass
        if self.settings.debug:
            print ("Creating usernames table")
        self.databaseTransaction("CREATE TABLE usernames (id INTEGER PRIMARY KEY, username TEXT)")
        if self.settings.debug:
            print ("Populating usernames table")
        for username in self.referenceData['commonUsernames']:
            self.databaseTransaction("INSERT INTO usernames (username) VALUES(?)", (str(username),))
        if self.settings.debug:
            print ("Creating passwords table")
        self.databaseTransaction("CREATE TABLE passwords (id INTEGER PRIMARY KEY, password TEXT)")
        if self.settings.debug:
            print ("Populating passwords table")
        for password in self.referenceData['commonPasswords']:
            self.databaseTransaction("INSERT INTO passwords (password) VALUES(?)", (str(password),))
        if self.settings.debug:
            print ("Creating hostnames table")
        self.databaseTransaction("CREATE TABLE hostnames (id INTEGER PRIMARY KEY, hostname TEXT)")
        if self.settings.debug:
            print ("Creating domains table")
        self.databaseTransaction("CREATE TABLE domains (id INTEGER PRIMARY KEY, domain TEXT)")
        if self.settings.debug:
            print ("Creating hosts table")
        self.databaseTransaction("CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT)")
        if self.settings.debug:
            print ("Creating openports table")
        self.databaseTransaction(
            "CREATE TABLE openPorts (id INTEGER PRIMARY KEY, hostID INTEGER, portNum INTEGER, portType INTEGER, FOREIGN KEY (hostID) REFERENCES hosts(id))")
        if self.settings.debug:
            print ("Creating findings table")
        self.databaseTransaction(
            "CREATE TABLE findings (id INTEGER PRIMARY KEY, openPortID INTEGER, dataSource TEXT, finding TEXT, FOREIGN KEY (openPortID) REFERENCES openPorts(id))")
        if self.settings.debug:
            print ("Populating initial details in hosts and openPorts tables")
        hostsInsert = ''
        for hostAddr in self.IPNetwork(self.targetNetwork):
            hostsInsert = hostsInsert + '\n("' + str(hostAddr) + '"),'
        hostsInsert = self.re.sub(',$', '', hostsInsert)
        self.databaseTransaction("INSERT INTO hosts (host) VALUES" + hostsInsert)
        openPortsInsert = ''
        for index in range(1, len(self.IPNetwork(self.targetNetwork))):
            openPortsInsert = openPortsInsert + '\n(' + str(index) + ', 0, 0),'
        openPortsInsert = self.re.sub(',$', '', openPortsInsert)
        self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, portType) VALUES" + openPortsInsert)

    def storeFinding(self, hostIP, portNum, portType, dataSource, finding):
        openPortID = self.getOpenPortID(hostIP, portNum, portType)
        currentRecordID = self.databaseTransaction("SELECT id FROM findings WHERE openPortID = ? AND dataSource = ?",
                                                   (openPortID, dataSource))
        if currentRecordID:
            self.databaseTransaction("UPDATE findings SET openPortID=?, dataSource=?, finding=? WHERE id = ?",
                                     (openPortID, dataSource, finding, currentRecordID[0][0]))
        else:
            self.databaseTransaction("INSERT INTO findings (openPortID, dataSource, finding) VALUES (?, ?, ?)",
                                     (openPortID, dataSource, finding))

    # ---- primary functionality ----#

    def checkSMBshares(self):
        print("SMB Non-Standard Share scan")
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            smbSharesProcess = self.subprocess.Popen(["smbclient", "-N", "-L", host[0]], stdout=self.subprocess.PIPE,
                                                     stderr=self.subprocess.STDOUT)
            smbSharesScanResult = self.re.sub('\t', '', self.re.sub(' +', ' ', self.grep(
                self.stripUnicode(smbSharesProcess.communicate()[0]), 'Disk')))
            try:
                smbSharesScanResultValue = smbSharesScanResult.split(' ')[0]
                smbSharesScanResultType = smbSharesScanResult.split(' ')[1]
            except IndexError:
                continue
            if smbSharesScanResultValue and smbSharesScanResultType:
                self.storeFinding(host[0], 445, 1, 'SMB share discovery',
                                  'Non-default share.\nNamed:\t' + smbSharesScanResultValue + '\nType:\t' + smbSharesScanResultType)

    def checkSMBshareAccess(self, username='', password=''):
        print("SMB Share Unauthenticated Access scan")
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            if username and password:
                smbSharesProcess = self.subprocess.Popen(["smbmap", "-H", host[0], "-U", username, "-P", password],
                                                         stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            elif username and not password:
                smbSharesProcess = self.subprocess.Popen(["smbmap", "-H", host[0], "-U", username],
                                                         stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            else:
                smbSharesProcess = self.subprocess.Popen(["smbmap", "-H", host[0]], stdout=self.subprocess.PIPE,
                                                         stderr=self.subprocess.STDOUT)
            smbSharesScanResult = self.re.sub("\n\t", "\n", self.re.sub("^\t", '', self.re.sub(' +', ' ', self.grepv(
                self.grepv(self.grepv(self.stripUnicode(smbSharesProcess.communicate()[0]), host[0]),
                           'Finding open SMB ports....'), '-----------'))))
            self.storeFinding(host[0], 445, 1, 'SMB share access checker',
                              'The following share accesses were found:\n' + smbSharesScanResult)

    def nbtScan(self):
        print("NBTscan")
        targets = self.databaseTransaction((
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=139 AND openPorts.portType = 1 ORDER BY hosts.host"))
        for host in targets:
            findingText = ''
            nbtProcess = self.subprocess.Popen(["nbtscan", "-v", "-s ~=~=~", host[0]], stdout=self.subprocess.PIPE,
                                               stderr=self.subprocess.STDOUT)
            nbtScanResult = self.stripUnicode(nbtProcess.communicate()[0])
            for code in self.referenceData['netbiosCodes']:
                netbiosCodeResult = self.grep(nbtScanResult, code[0])
                if netbiosCodeResult:
                    if self.re.search('MAC', netbiosCodeResult):
                        netbiosValue = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[2]
                        netbiosType = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[1]
                    else:
                        netbiosType = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[2]
                        netbiosValue = str.replace(netbiosCodeResult.upper(), code[0], code[1]).split("~=~=~")[1]
                    findingText = findingText + "\n" + netbiosType + ":" + netbiosValue
                    if self.re.search("Workstation Service", netbiosType):
                        netbiosValue = self.re.sub(' ', '', netbiosValue)
                        checkExistsResult = self.databaseTransaction(
                            "SELECT DISTINCT hostname FROM hostnames WHERE hostname = ?", (str(netbiosValue).lower(),))
                        if not checkExistsResult:
                            self.databaseTransaction('INSERT INTO hostnames (hostname) VALUES(?)',
                                                     (str(netbiosValue).lower(),))
                    if self.re.search("Domain / Workgroup Name", netbiosType):
                        netbiosValue = self.re.sub(' ', '', netbiosValue)
                        checkExistsResult = self.databaseTransaction(
                            "SELECT DISTINCT domain FROM domains WHERE domain = ?", (str(netbiosValue).lower(),))
                        if not checkExistsResult:
                            self.databaseTransaction('INSERT INTO domains (domain) VALUES(?)',
                                                     (str(netbiosValue).lower(),))
                            self.databaseTransaction('INSERT INTO domains (domain) VALUES(?)',
                                                     (str(netbiosValue).lower() + '.local',))
                            self.databaseTransaction('INSERT INTO domains (domain) VALUES(?)',
                                                     (str(netbiosValue).lower() + '.lan',))
            self.storeFinding(host[0], 139, 1, 'NBTscan', self.re.sub("^\n", '', findingText))

    def portScan(self, allPorts=False):
        print("Running targeted portscan")
        print("You may also want a full port scan with service detection, for example:")
        print("   nmap -sV -sS --open -n -vvvv -T4 -Pn -p- -oA nmapTcpScan " + self.targetNetwork)
        if allPorts:
            for targetPort in range(1, 65535):
                if self.settings.debug:
                    print("Scanning to see if TCP/" + str(targetPort) + " is open on any in-scope IP")
                self.singlePortScan_TCP(str(targetPort))
        else:
            for targetPort in self.settings.portsForScanning_TCP:
                if self.settings.debug:
                    print("Scanning to see if TCP/" + str(targetPort) + " is open on any in-scope IP")
                self.singlePortScan_TCP(str(targetPort))
        for targetPort in self.settings.portsForScanning_UDP:
            if self.settings.debug:
                print("Scanning to see if UDP/" + str(targetPort) + " is open on any in-scope IP")
            self.singlePortScan_UDP(str(targetPort))

    def runDefaultTools(self):
        print('Running default tools:')
        self.nbtScan()
        self.checkRDNSForIP()
        self.smbVersionScan()
        self.smbUsersScan()
        self.checkSMBshares()
        self.checkSMBshareAccess()
        self.checkMS08067()
        self.checkSSHversion()
        self.checkSNMPForDefaultCommunities()
        self.checkDNSForHostname()
        self.checkDNSForAXFR()
        self.checkMSSQLDefaultCreds()
        self.checkFingerUsers()
        self.checkSMTPForDomains()
        self.checkSMTPUserEnum()

    def singlePortScan_TCP(self, targetPort):
        nm = self.nmap.PortScanner()
        nm.scan(self.targetNetwork, targetPort, self.settings.nmapGenericSettingsTCP)
        for hostIP in nm.all_hosts():
            if self.settings.debug:
                print("TCP Port " + targetPort + " found open on host " + hostIP)
            hostID = self.getHostID(hostIP)
            if self.getOpenPortID(hostIP, targetPort, 1):
                if self.settings.debug:
                    print("TCP Port already found, skipping...")
            else:
                self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, portType) VALUES(?, ?, 1)",
                                         (hostID, targetPort))

    def singlePortScan_UDP(self, targetPort):
        process = self.subprocess.Popen(
            ["nmap", "-oG", "-", "-p", targetPort, "--open", "-n", "-Pn", "-sU", "-T5", self.targetNetwork],
            stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
        resultsFull = self.stripUnicode(process.communicate()[0])
        resultsFiltered = self.grep(resultsFull, targetPort + '/open/udp').splitlines()
        for line in resultsFiltered:
            try:
                hostIP = line.split(" ()")[0].split("Host: ")[1]
            except IndexError:
                continue
            if self.settings.debug:
                print("UDP Port " + targetPort + " found open on host " + hostIP)
            hostID = self.getHostID(hostIP)
            if self.getOpenPortID(hostIP, targetPort, 2):
                if self.settings.debug:
                    print("UDP Port already found, skipping...")
            else:
                self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, portType) VALUES(?, ?, 2)",
                                         (hostID, targetPort))

    def smbVersionScan(self):
        print("SMB Version scan")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smb/smb_version')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + host[0] + '/32')
            msfFullResult = self.executeMSFcommand(self.msfConsole, 'run')
            msfResult = self.grep(msfFullResult['data'], host[0])
            if msfResult == '':
                if self.settings.debug:
                    print("Host didn't respond to scan, trying one last time")
                msfFullResult = self.executeMSFcommand(self.msfConsole, 'run')
                msfResult = self.grep(msfFullResult['data'], host[0])
            try:
                portNum = int(msfResult.split("Host is running ")[0].split(":")[1].split(" ")[0])
                msfFinding = msfResult.split("Host is running ")[1]
            except IndexError:
                continue
            if msfFinding and portNum:
                self.storeFinding(host[0], portNum, 1, "SMB Version Scan", msfFinding)

    def smbUsersScan(self):
        print("SMB Enumerable Users scan")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smb/smb_enumusers')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND (openPorts.portNum=445 OR openPorts.portNum=139) AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + host[0] + '/32')
            msfFullResult = self.executeMSFcommand(self.msfConsole, 'run')
            msfResult = self.grep(msfFullResult['data'], host[0])
            if msfResult == '':
                if self.settings.debug:
                    print("Host didn't respond to scan, trying one last time")
                msfFullResult = self.executeMSFcommand(self.msfConsole, 'run')
                msfResult = self.grep(msfFullResult['data'], host[0])
            try:
                portNum = int(msfResult.split(" - ")[0].split(":")[1].split(" ")[0])
                msfFindingDetail = msfResult.split(" [ ")[1].split(" ]")[0]
            except IndexError:
                continue
            if msfFindingDetail:
                msfFinding = 'Users found:\n' + msfFindingDetail
            else:
                msfFinding = 'No users found on host (probably no permissions)'
            self.storeFinding(host[0], portNum, 1, "SMB user discovery",
                              msfFinding + "\n\n This also implies unauthenticated RPC")

    def checkMS08067(self):
        print("Checking for MS08-067 vulnerable")
        self.executeMSFcommand(self.msfConsole, 'use exploit/windows/smb/ms08_067_netapi')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=445 AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOST ' + host[0])
            msfFullResult = self.executeMSFcommand(self.msfConsole, 'check')
            msfResult = self.grep(msfFullResult['data'], host[0])
            if msfResult == '':
                if self.settings.debug:
                    print("Host didn't respond to scan, trying one last time")
                msfFullResult = self.executeMSFcommand(self.msfConsole, 'check')
                msfResult = self.grep(msfFullResult['data'], host[0])
            try:
                msfFinding = self.grepv(msfResult.split(":445 ")[1], 'The target is not exploitable')
            except IndexError:
                continue
            if msfFinding:
                self.storeFinding(host[0], 445, 1, "MS08-067 checker",
                                  msfFinding + " Use something like this in MSF:\n\nuse exploit/windows/smb/ms08_067_netapi\nset PAYLOAD windows/meterpreter/bind_tcp\nset RHOST " +
                                  host[0] + "\nexploit")

    def checkMS08067(self):
        print("Checking for MS08-067 vulnerable")
        self.executeMSFcommand(self.msfConsole, 'use exploit/windows/smb/ms08_067_netapi')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=445 AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOST ' + host[0])
            msfFullResult = self.executeMSFcommand(self.msfConsole, 'check')
            msfResult = self.grep(msfFullResult['data'], host[0])
            if msfResult == '':
                if self.settings.debug:
                    print("Host didn't respond to scan, trying one last time")
                msfFullResult = self.executeMSFcommand(self.msfConsole, 'check')
                msfResult = self.grep(msfFullResult['data'], host[0])
            try:
                msfFinding = self.grepv(msfResult.split(":445 ")[1], 'The target is not exploitable')
            except IndexError:
                continue
            if msfFinding:
                self.storeFinding(host[0], 445, 1, "MS08-067 checker",
                                  msfFinding + " Use something like this in MSF:\n\nuse exploit/windows/smb/ms08_067_netapi\nset PAYLOAD windows/meterpreter/bind_tcp\nset RHOST " +
                                  host[0] + "\nexploit")

    def checkMS17010(self):
        print("Checking for MS17-010 vulnerable")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smb/smb_ms17_010')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=445 AND openPorts.portType = 1 ORDER BY hosts.host")
        for host in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + host[0] + '/32')
            msfFullResult = self.executeMSFcommand(self.msfConsole, 'run')
            msfResult = self.grep(msfFullResult['data'], host[0])
            if msfResult == '':
                if self.settings.debug:
                    print("Host didn't respond to scan, trying one last time")
                msfFullResult = self.executeMSFcommand(self.msfConsole, 'run')
                msfResult = self.grep(msfFullResult['data'], host[0])
            try:
                msfFinding = self.grepv(msfResult.split(":445 ")[1], 'The target is not exploitable')
            except IndexError:
                continue
            if msfFinding:
                self.storeFinding(host[0], 445, 1, "MS17-010 checker",
                                  msfFinding + " Use something like this in MSF:\n\nuse exploit/windows/smb/ms17_010_eternalblue\nset PAYLOAD windows/meterpreter/bind_tcp\nset RHOST " +
                                  host[0] + "\nexploit")

    def checkDNSForAXFR(self):
        print ("Checking for AXFR on DNS servers")
        dnsServers = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=53 AND openPorts.portType = 2 ORDER BY hosts.host")
        domainResults = self.databaseTransaction("SELECT domain FROM domains ORDER BY domain")
        if domainResults:
            for domain in domainResults:
                for dnsServer in dnsServers:
                    axfrProcess = self.subprocess.Popen(["dig", "+tries=" + dnsTimeoutSeconds, "+time=" + dnsTimeoutSeconds, "axfr", domain[0], '@' + dnsServer[0]],
                                                        stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
                    axfrResult = self.stripUnicode(axfrProcess.communicate()[0])
                    if self.grep(axfrResult, ';; Query time:'):
                        self.storeFinding(dnsServer[0], 53, 2, 'AXFR Checker', axfrResult)
                        print (axfrResult)

    def checkDNSForHostname(self):
        print("Checking for hostnames in DNS")
        domains = self.databaseTransaction("SELECT domain FROM domains ORDER BY domain")
        domains.append([''])
        dnsServers = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=53 AND openPorts.portType = 2 ORDER BY hosts.host")
        hostnameResults = self.databaseTransaction("SELECT hostname FROM hostnames ORDER BY hostname")
        if hostnameResults and dnsServers:
            for domain in domains:
                if domain[0]:
                    domainPostfix = "." + domain[0]
                else:
                    domainPostfix = ''
                for hostname in hostnameResults:
                    for dnsServer in dnsServers:
                        process = self.subprocess.Popen(["host", "-W " + dnsTimeoutSeconds, hostname[0] + domainPostfix, dnsServer[0]],
                                                        stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
                        resultFull = self.stripUnicode(process.communicate()[0])
                        try:
                            result = self.grep(resultFull, ' has address ')
                            resultIP = self.grep(result, hostname[0]).split(' has address ')[1]
                        except IndexError:
                            continue
                        self.storeFinding(resultIP, 0, 0, 'Host in DNS Checker',
                                          'DNS Server ' + dnsServer[0] + ' reports: \n' + result)

    def checkRDNSForIP(self):
        print("Checking for IP in rDNS")
        hosts = self.databaseTransaction("SELECT host FROM hosts ORDER BY host")
        dnsServers = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=53 AND openPorts.portType = 2 ORDER BY hosts.host")
        if hosts and dnsServers:
            for host in hosts:
                for dnsServer in dnsServers:
                    process = self.subprocess.Popen(["host", "-W " + dnsTimeoutSeconds, host[0], dnsServer[0]],
                                                    stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
                    resultFull = self.stripUnicode(process.communicate()[0])
                    try:
                        result = self.grep(resultFull, ' domain name pointer ')
                    except IndexError:
                        continue
                    if result:
                        self.storeFinding(host[0], 0, 0, 'IP in rDNS Checker',
                                      'DNS Server ' + dnsServer[0] + ' reports: \n' + result)
                        try:
                            resultHostname = result.split(' domain name pointer ')[1].split('.')[0]
                        except IndexError:
                            try:
                                resultHostname = result.split(' domain name pointer ')[1]
                            except IndexError:
                                continue
                        if resultHostname:
                            checkExistsResult = self.databaseTransaction(
                                "SELECT DISTINCT hostname FROM hostnames WHERE hostname = ?",
                                (str(resultHostname).lower(),))
                            if not checkExistsResult:
                                self.databaseTransaction('INSERT INTO hostnames (hostname) VALUES(?)',
                                                         (str(resultHostname).lower(),))
                        try:
                            resultDomain = self.re.sub('\.$', '', result.split(' domain name pointer ')[1].split('.', 1)[1])
                        except IndexError:
                            try:
                                resultDomain = result.split(' domain name pointer ')[1].split('.', 1)[1]
                            except IndexError:
                                continue
                        if resultDomain:
                            checkExistsResult = self.databaseTransaction(
                                "SELECT DISTINCT domain FROM domains WHERE domain = ?", (str(resultDomain).lower(),))
                            if not checkExistsResult:
                                self.databaseTransaction('INSERT INTO domains (domain) VALUES(?)',
                                                         (str(resultDomain).lower(),))
                                self.databaseTransaction('INSERT INTO domains (domain) VALUES(?)',
                                                         (str(resultDomain).lower() + '.local',))
                                self.databaseTransaction('INSERT INTO domains (domain) VALUES(?)',
                                                         (str(resultDomain).lower() + '.lan',))

    def checkSSHversion(self):
        print("Checking for SSH protocol versions in place")
        sshServers = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=22 AND openPorts.portType = 1 ORDER BY hosts.host")
        for server in sshServers:
            sshCheckProcess = self.subprocess.Popen(
                ["ssh", "-vN", "-oBatchMode=yes", "-oStrictHostKeyChecking=no", "-oUserKnownHostsFile=/dev/null",
                 server[0]], stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
            sshCheckResultFull = self.stripUnicode(sshCheckProcess.communicate()[0])
            try:
                sshCheckResult = self.grep(sshCheckResultFull, "remote software version").split("debug1: ")[1].split(
                    ", remote software version")[0]
            except IndexError:
                continue
            if not self.re.search('Remote protocol version 2.0', sshCheckResult):
                self.storeFinding(server[0], 22, 1, 'SSH Protocol Version Checker', sshCheckResult)

    def checkSNMPForDefaultCommunities(self):
        print("Check for default community strings")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/snmp/snmp_login')
        self.executeMSFcommand(self.msfConsole, 'set VERSION all')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=161 AND openPorts.portType = 2 ORDER BY hosts.host")
        for target in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + target[0] + '/32')
            snmpCheckResultFull = self.executeMSFcommand(self.msfConsole, 'run')
            snmpCheckResult = self.grepv(self.grepv(snmpCheckResultFull['data'], 'Scanned 1 of 1 hosts'),
                                         'Auxiliary module execution completed')
            if snmpCheckResult:
                self.storeFinding(target[0], 161, 2, 'SNMP Default Communities Checker', snmpCheckResult)

    def checkMSSQLDefaultCreds(self):
        print("MSSQL Default Creds Checker")
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=1433 AND openPorts.portType = 1 ORDER BY hosts.host")
        usernameResults = self.databaseTransaction("SELECT username FROM usernames ORDER BY username")
        passwordResults = self.databaseTransaction("SELECT password FROM passwords ORDER BY password")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/mssql/mssql_login')
        for target in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + target[0] + '/32')
            for username in usernameResults:
                self.executeMSFcommand(self.msfConsole, 'set USERNAME ' + username[0])
                for password in passwordResults:
                    self.executeMSFcommand(self.msfConsole, 'set PASSWORD ' + password[0])
                    resultsFull = 'Attempt with ' + username[0] + " / " + password[0] + ' against ' + target[0] + '\n'
                    resultsFull = resultsFull + self.executeMSFcommand(self.msfConsole, 'run')
                    results = self.grepv(self.grepv(resultsFull, 'Scanned 1 of 1 hosts'),
                                         'Auxiliary module execution completed')
                    if results:
                        self.storeFinding(target[0], 1433, 1, 'MSSQL Default Creds Checker', results)

    def checkFingerUsers(self):
        print("Checking for finger service user enumeration")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/finger/finger_users')
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=79 AND openPorts.portType = 1 ORDER BY hosts.host")
        for target in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + target[0] + '/32')
            resultsFull = 'Attempt against ' + target[0] + '\n'
            resultsFull = resultsFull + self.executeMSFcommand(self.msfConsole, 'run')
            results = self.grepv(self.grepv(resultsFull, 'Scanned 1 of 1 hosts'),
                                 'Auxiliary module execution completed')
            if results:
                self.storeFinding(target[0], 79, 1, 'Finger user enum checker', results)

    def checkSMTPForDomains(self):
        print("Checking SMTP service for domain info leaks")
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=25 AND openPorts.portType = 1 ORDER BY hosts.host")
        self.executeMSFcommand(self.msfConsole, 'use auxiliary/scanner/smtp/smtp_ntlm_domain')
        for target in targets:
            self.executeMSFcommand(self.msfConsole, 'set RHOSTS ' + target[0] + '/32')
            resultsFull = 'Attempt against ' + target[0] + '\n'
            resultsFull = resultsFull + self.executeMSFcommand(self.msfConsole, 'run')
            results = self.grepv(self.grepv(resultsFull, 'Scanned 1 of 1 hosts'),
                                 'Auxiliary module execution completed')
            if results:
                self.storeFinding(target[0], 25, 1, 'SMTP Domain Info Leak', results)

    def checkSMTPUserEnum(self):
        print("Performing SMTP User Enumeration")
        usernameResults = self.databaseTransaction("SELECT username FROM usernames ORDER BY username")
        targets = self.databaseTransaction(
            "SELECT DISTINCT hosts.host FROM hosts, openPorts WHERE hosts.id=openPorts.hostID AND openPorts.portNum=25 AND openPorts.portType = 1 ORDER BY hosts.host")
        for target in targets:
            for username in usernameResults:
                resultsFull = 'Attempt against ' + target[0] + ' with user ' + username[0] + ' using the VRFY method\n'
                process = self.subprocess.Popen(["smtp-user-enum", "-M", "VRFY", "-u", username[0], "-t", target[0]],
                                                stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
                resultsFull = resultsFull + self.stripUnicode(process.communicate()[0])
                resultsFiltered = self.grepv(self.grepv(self.grepv(self.grepv(self.grepv(self.grepv(self.grepv(
                    self.grepv(self.grepv(
                        self.grepv(self.grepv(self.grepv(resultsFull, '------------------'), 'Scan Information'),
                                   'Mode ..............'), 'Worker Processes ..'), 'Target count ......'),
                    'Username count ....'), 'Target TCP port ...'), 'Query timeout .....'), 'Target domain .....'),
                    '######## Scan '), ' queries in '), '0 results.')
                if resultsFiltered:
                    self.storeFinding(target[0], 25, 1, 'SMTP User Enumeration', resultsFiltered)
                # ----------
                resultsFull = 'Attempt against ' + target[0] + ' with user ' + username[0] + ' using the EXPN method\n'
                process = self.subprocess.Popen(["smtp-user-enum", "-M", "EXPN", "-u", username[0], "-t", target[0]],
                                                stdout=self.subprocess.PIPE, stderr=self.subprocess.STDOUT)
                resultsFull = resultsFull + self.stripUnicode(process.communicate()[0])
                resultsFiltered = self.grepv(self.grepv(self.grepv(self.grepv(self.grepv(self.grepv(self.grepv(
                    self.grepv(self.grepv(
                        self.grepv(self.grepv(self.grepv(resultsFull, '------------------'), 'Scan Information'),
                                   'Mode ..............'), 'Worker Processes ..'), 'Target count ......'),
                    'Username count ....'), 'Target TCP port ...'), 'Query timeout .....'), 'Target domain .....'),
                    '######## Scan '), ' queries in '), '0 results.')
                if resultsFiltered:
                    self.storeFinding(target[0], 25, 1, 'SMTP User Enumeration', resultsFiltered)
