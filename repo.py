from dataclasses import dataclass
from pymongo import MongoClient




@dataclass
class Endpoint:
    """Class for keeping track of an endpoint in inventory."""
    _id: str
    host: str
    port: str
    protocol: str
    service: str
    oids: dict[str,dict[str,str]]

    def __eq__(self, other) -> float:
        return self._id == other._id
    
    def __init__(self, host, portProtocol, service="", oids=None):
        if oids is None:
            oids = {}
        self._id = f"{host} {portProtocol}"
        self.host = host
        self.port = portProtocol.split('/')[0].strip()
        self.protocol = portProtocol.split('/')[1].strip()
        self.service = service
        self.oids = oids


    def add_oid(self, oid, status="Open", notes=""):
        self.oids[oid] = {"status":status,"notes":notes}

    def update(self, other):
        self.oids.update(other.oids)
        if other.service:
            self.service = other.service


    def json(self):
        return {
            "_id":self._id,
            "host":self.host,
            "port":self.port,
            "protocol":self.protocol,
            "service":self.service,
            "oids":self.oids
        }


@dataclass
class Vulnerability:
    """Class for keeping track of a vulnerability in inventory."""
    _id: str
    name: str
    family: str
    threat: str
    cvss: str
    date: str
    value: str
    solution: str
    description: str
    host: str = ""
    portProtocol: str = ""

    def __eq__(self, other) -> float:
        return self._id == other._id

    def json(self):
        return {
            "_id":self._id,
            "name":self.name,
            "family":self.family,
            "threat":self.threat,
            "cvss":self.cvss,
            "value":self.value,
            "solution":self.solution,
            "description":self.description
        }


@dataclass
class Repo:
    """Class for database management."""
    database: str
    collections: dict[str,str]

    def __init__(self, database, url):
    
        # Provide the mongodb atlas url to connect python to mongodb using pymongo
        CONNECTION_STRING = url
        
        # Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
        client = MongoClient(CONNECTION_STRING)
        
        # Create the database for our example (we will use the same database throughout the tutorial
        self.database = client[database]

        self.collections = {"vulnerability":self.database["vulnerability"],"host":self.database["host"]}

    def get_endpoint(self, host, portProtocol):

        item = self.collections['host'].find_one({"_id" : f"{host.strip()} {portProtocol.strip()}"})
        if item:
            endpoint = Endpoint(item['host'], f"{item['port']}/{item['protocol']}", oids=item["oids"], service=item['service'])
        else:
            endpoint = None
        return endpoint

    #db.testing.update({"_id":"126"},{"$set":{"l":"1334"}},{"upsert":true})

#   result.acknowledged    result.modified_count  result.upserted_id     
#   result.matched_count   result.raw_result  
#   {'n': 1, 'nModified': 1, 'ok': 1.0, 'updatedExisting': True}
    def add_endpoint(self, newEndpoint: Endpoint):
        fetchEndpoint = self.get_endpoint(newEndpoint._id.split()[0], newEndpoint._id.split()[1])
        if fetchEndpoint:
            fetchEndpoint.update(newEndpoint)
            newEndpoint = fetchEndpoint
        return self.collections['host'].update_one({"_id":newEndpoint._id},{"$set":newEndpoint.json()},upsert=True)

    def add_vulnerability(self, vulnerability: Vulnerability):
        return self.collections['vulnerability'].update_one({"_id":vulnerability._id},{"$set":vulnerability.json()},upsert=True)

    def get_all_oids(self):
        return [oid['_id'] for  oid in self.collections['vulnerability'].find(projection={'_id':1})]

    def get_all_host(self):
        return self.collections['host'].find()
    
    def find_vuln_by(self, oid):
        return self.collections['vulnerability'].find_one({"_id":oid})
    
    def get_summary(self):
        vulnerabilities = []
        for host in self.get_all_host():
            for oid, data in host['oids'].items():
                vuln = self.find_vuln_by(oid)
                if data['status'] == "Open":
                    vuln['status'] = data['status']
                    vuln['notes'] = data['notes']
                    vuln.update(host)
                    vuln.pop('oids')
                    vuln.pop('_id')
                    vuln['vulnerability ID'] = oid
                    #{'cvss': '6.4', 'description': '', 'family': 'General', 'name': 'MQTT Broker Does Not Require Authentication', 'solution': '', 'threat': 'Medium', 'value': 'AV:N/AC:L/Au:N/C:P/I:P/A:N', 'status': 'Open', 'notes': '', 'host': '1.2.3.4', 'port': '1456', 'protocol': 'tcp', 'service': '', 'vulnerability ID': '1.3.6.1.4.1.25623.1.0.140167'}
                    vulnerabilities.append(vuln)
        return vulnerabilities
