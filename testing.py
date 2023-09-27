import configparser
from repo import Repo, Endpoint
from loggingHelper import logger
from datetime import datetime
from nessusParser import NessusParser




reportName = "vulnerabilities"
repo = Repo('vuln_management', "mongodb://localhost")
config = configparser.ConfigParser()
config.read('manager.conf')


nessus = NessusParser(config['nessus']['url'],
                      config['nessus']['port'],
                      config['nessus']['access_key'],
                      config['nessus']['secret_key'])

nessus.connect()

testEndpoint = Endpoint(ip='207.135.208.73', port='8006', protocol='tcp', service='www', hostnames={'pve003-nyc.edgeuno.net', '207-135-208-73.seaborn.net'}, vulnerabilities={'142960': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}, '85582': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}, '51192': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}})

print(testEndpoint.json())
# repo.add_endpoint()
