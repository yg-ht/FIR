class FastInitialRecon:
    #python3 modules
    import settings
    import os
    import nmap
    import sqlite3
    from sqlite3 import Error

    #custom modules
    import definitions

    def __init__(self, targetNetwork):
        from netaddr import IPNetwork

        try:
            self.os.remove(self.settings.dbFile)
        except OSError:
            pass

        self.databaseTransaction("CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT)")
        self.databaseTransaction("CREATE TABLE openPorts (id INTEGER PRIMARY KEY, hostID INTEGER, portNum INTEGER, TCP INTEGER, FOREIGN KEY (hostID) REFERENCES hosts(id))")
        self.databaseTransaction("CREATE TABLE findings (id INTEGER PRIMARY KEY, openPortID INTEGER, finding TEXT, FOREIGN KEY (openPortID) REFERENCES openPorts(id))")
        for hostAddr in IPNetwork(targetNetwork):
            self.databaseTransaction("INSERT INTO hosts (host) VALUES(?)", (str(hostAddr),))

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
            print("TCP Port "+targetPort+" found open on host " + IP)
            hostIDResult = self.databaseTransaction("SELECT id FROM hosts WHERE host=?", (str(IP),))
            hostID = hostIDResult[0][0]
            self.databaseTransaction("INSERT INTO openPorts (hostID, portNum, TCP) VALUES(?, ?, 1)", (hostID, targetPort))

    def getDiscoveredOpenPorts(self):
        results = self.databaseTransaction("SELECT hosts.host as IP, openPorts.portNum as Port, openPorts.TCP FROM hosts, openPorts WHERE hosts.id=openPorts.id")
        return results

    def printDiscoveredOpenPorts(self):
        results = self.getDiscoveredOpenPorts()
        for result in results:
            if (result[2]):
                print(result[0] + " has open TCP port " + str(result[1]))
            else:
                print(result[0] + " has open UDP port " + str(result[1]))
