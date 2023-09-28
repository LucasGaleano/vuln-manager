from dataclasses import dataclass, asdict, field
from pymongo import MongoClient
import time
from loggingHelper import logger
import urllib.parse



@dataclass
class Endpoint:
    """Class for keeping track of an endpoint in inventory."""
    _id: str = field(init=False, compare=True)
    ip: str = field(compare=False)  
    port: str = field(compare=False)
    protocol: str = field(compare=False)
    service: str = field(compare=False)
    hostnames: list[str] = field(compare=False, default_factory=list)
    vulnerabilities: dict[str,dict[str,str]] = field(compare=False, default_factory=dict)
    
    def __post_init__(self):
        self._id = f"{self.ip}:{self.port}/{self.protocol}"

    def add_vulnerability(self, id, status="Open", notes="", findingTime=None):
        if not findingTime:
            findingTime = time.time()
        self.vulnerabilities[id] = {"status":status,"notes":notes, "finding_time": findingTime, "solved_time": ''}

    def add_hostname(self, hostname):
        # cannot use Set() for the pymongo integration
        if hostname not in self.hostnames:
            self.hostnames.append(hostname)
    
    def solve_vulnerability(self, id:str|int):
        self.vulnerabilities[str(id)]['status'] = "Solved"
        self.vulnerabilities[str(id)]['solved_time'] = time.time()

    def update_vulnerabilities(self, other):
        vulnSolved = []
        vulnMissing = self.vulnerabilities.keys() - other.vulnerabilities.keys()
        vulnAdded = other.vulnerabilities.keys() - self.vulnerabilities.keys()
        for id in vulnAdded:
            self.add_vulnerability(id)
        for id in vulnMissing:
            if self.vulnerabilities[id]['status'] == "Open":
                self.solve_vulnerability(id)
                vulnSolved.append(id)

        return (vulnAdded, set(vulnSolved))


    def json(self):
        return asdict(self)


@dataclass
class Vulnerability:
    """Class for keeping track of a vulnerability in inventory."""
    _id: str
    name: str = ""
    family: str = ""
    cvss3: str = ""
    severity: str = ""
    cpe: str = ""
    threat: str = ""
    cve: str = ""
    description: str = ""
    solution: str = ""
    seeAlso: str = ""
    synopsis: str = ""
    cvss3Vector: str = ""
    age: str = ""

    def __eq__(self, other) -> float:
        return self._id == other._id

    def json(self):
        return asdict(self)


@dataclass
class Repo:
    """Class for database management."""
    _database: str
    _client: str
    databaseName: str
    collections: dict[str,str]
    user: str
    password: str

    def __init__(self, databaseName, host, user, password):


        self.user = urllib.parse.quote_plus(user)
        self.password = urllib.parse.quote_plus('pass/word')
        self.databaseName = databaseName
    
        # Provide the mongodb atlas url to connect python to mongodb using pymongo
        CONNECTION_STRING = "mongodb://%s:%s" + "@" + host
        
        # Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
        self._client = MongoClient(CONNECTION_STRING % (user,password))
        
        # Create the database for our example (we will use the same database throughout the tutorial
        self._database = self._client[databaseName]

        self.collections = {"vulnerability":self._database["vulnerability"],"host":self._database["host"]}

    def __enter__(self):
        print('enter')
        return self

    def __exit__(self, type, value, traceback):
        print('exit')
        self._client.close()

    def get_endpoint(self, host, portProtocol):

        item = self.collections['host'].find_one({"_id" : f"{host.strip()} {portProtocol.strip()}"})
        if item:
            endpoint = Endpoint(item['host'], f"{item['port']}/{item['protocol']}", oids=item["oids"], service=item['service'])
        else:
            endpoint = None
        return endpoint
    
    def get_endpoint_by_id(self, id: str) -> Endpoint:

        item = self.collections['host'].find_one({"_id" : id})
        if item:
            item.pop('_id')
            endpoint = Endpoint(**item)
        else:
            endpoint = None
        return endpoint

    #db.testing.update({"_id":"126"},{"$set":{"l":"1334"}},{"upsert":true})

#   result.acknowledged    result.modified_count  result.upserted_id     
#   result.matched_count   result.raw_result  
#   {'n': 1, 'nModified': 1, 'ok': 1.0, 'updatedExisting': True}
    def add_endpoint(self, newEndpoint: Endpoint):
        return self.collections['host'].update_one({"_id":newEndpoint._id},{"$set":newEndpoint.json()},upsert=True)

    def add_vulnerability(self, vulnerability: Vulnerability):
        return self.collections['vulnerability'].update_one({"_id":vulnerability._id},{"$set":vulnerability.json()},upsert=True)

    def get_all_oids(self):
        return [oid['_id'] for  oid in self.collections['vulnerability'].find(projection={'_id':1})]

    def get_all_host(self):
        return self.collections['host'].find()
    
    def find_vuln_by_id(self, id):
        vuln = self.collections['vulnerability'].find_one({"_id":id})
        return Vulnerability(**vuln)
    
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
