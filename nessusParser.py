from tenable.io import TenableIO
from tenable.nessus import Nessus
import logging
from repo import Endpoint, Vulnerability
from dataclasses import dataclass, field
import xml.etree.ElementTree as ET
logging.basicConfig(level=logging.DEBUG)


@dataclass
class Scan():

    id: str
    name: str
    live_results: int
    control: bool
    enabled: bool
    starttime: str
    rrules: str
    timezone: str
    owner: str
    user_permissions: int
    shared: bool
    uuid: str
    status: str
    creation_date: int
    last_modification_date: int
    read: bool
    type: str
    folder_id: int
    folder_name: str


    def folderNameNoSpaces(self) -> str:
        return '_'.join(self.folder_name.split())
    
    def completed(self) -> bool:
        return self.status == "completed"


@dataclass
class NessusParser():

    _url: str
    _port: int
    _access_key: str
    _secret_key: str
    _nessus: Nessus = field(init=False)

    def connect(self):
        
        self._nessus = Nessus(
            url=self._url,
            port=self._port,
            access_key=self._access_key,
            secret_key=self._secret_key
        )

    def get_all_vulnerabilities(self, scanID: int):
        vulns = []
        for v in self._nessus.scans.results(scanID)['vulnerabilities']:
            vulns.append(Vulnerability(_id= v['plugin_id'],
                                        name=v['plugin_name'],
                                        family=v['plugin_family'],
                                        cvss3=v['score'],
                                        severity=v['severity'],
                                        vpr_score=v['vpr_score'],
                                        cpe=v['cpe']))
        return vulns

            # pluginInfo = self._nessus.plugins.plugin_details(v['plugin_id'])
            # vulns.append({i['attribute_name']:i['attribute_value'] for i in pluginInfo['attributes']})

            # vulns.append(pluginInfo)
            # return vulns

    def get_all_endpoints(self, scanID: int):
        hosts = []
        for h in self._nessus.scans.results(scanID)['hosts']:               
            hostname = h['hostname']
            hostID = h['host_id']
            hostDetails = self._nessus.scans.host_details(scanID, host_id=hostID)
            hostIP = hostDetails['info']['host-ip']
            pluginPortsScanner = [v['plugin_id'] for v in hostDetails['vulnerabilities'] if v['plugin_family']=='Port scanners']
            for plugins in pluginPortsScanner:
                pluginOutput = self._nessus.scans.plugin_output(scanID,hostID,plugins)
                for portProtocolService in [i for output in pluginOutput['outputs'] for i in output['ports']]:
                    # example ['22 / tcp / ssh', '111 / tcp / ', '3128 / tcp / www', '8006 / tcp / www']
                    hostPort = portProtocolService.split('/')[0].strip()
                    hostProtocol = portProtocolService.split('/')[1].strip()
                    try:
                        hostService = portProtocolService.split('/')[2].strip()
                    except:
                        hostService = None
                    hosts.append(Endpoint(ip=hostIP, hostname=[hostname], port=hostPort, protocol=hostProtocol, service=hostService))
        return hosts
        

    def scan_export_request(self, scanID: int):

        endpoints = {}
        vulnerabilities = []
        with open('temporal.xml','wb') as f:
            self._nessus.scans.export_scan(scanID, fobj=f,format='nessus')
        xml = ET.parse('temporal.xml').getroot()
        for category in xml: # Policy, Report
            if category.tag == 'Report':
                for reporthost in category:
                    for hostProperties in reporthost:
                        if hostProperties.tag == 'HostProperties':
                            for data in hostProperties:
                                if data.attrib['name'] == 'host-ip':
                                    hostIP = data.text
                                if data.attrib['name'] == 'host-rdns':
                                    hostrdns = data.text
                                if data.attrib['name'] == 'HOST_END_TIMESTAMP':
                                    hostTimeEndScan = data.text
                        if hostProperties.tag == "ReportItem":
                            if hostProperties.attrib['severity'] != '0':
                                newEndpoint = Endpoint(ip=hostIP, 
                                        hostnames=[reporthost.attrib['name']],
                                        port=hostProperties.attrib['port'],
                                        protocol=hostProperties.attrib['protocol'],
                                        service=hostProperties.attrib['svc_name'])
                                newEndpoint.add_hostname(hostrdns)
                                pluginID = hostProperties.attrib['pluginID']
                                endpoint = endpoints.get(newEndpoint._id, newEndpoint)
                                endpoint.add_vulnerability(pluginID ,
                                                        findingTime=hostTimeEndScan)
                                endpoints[endpoint._id] = endpoint
                                vuln = {'family':hostProperties.attrib['pluginFamily'], 
                                        'severity':hostProperties.attrib['severity'],
                                        '_id':hostProperties.attrib['pluginID']}
                                for field in hostProperties:
                                    if field.tag == 'cpe':
                                        vuln['cpe'] = field.text
                                    if field.tag == 'description':
                                        vuln['description'] = field.text
                                    if field.tag == 'plugin_name':
                                        vuln['name'] = field.text
                                    if field.tag == 'risk_factor':
                                        vuln['threat'] = field.text
                                    if field.tag == 'see_also':
                                        vuln['seeAlso'] = field.text
                                    if field.tag == 'solution':
                                        vuln['solution'] = field.text
                                    if field.tag == 'synopsis':
                                        vuln['synopsis'] = field.text
                                    if field.tag == 'age_of_vuln':
                                        vuln['age'] = field.text
                                    if field.tag == 'cve':
                                        vuln['cve'] = field.text
                                    if field.tag == 'cvss3_base_score':
                                        vuln['cvss3'] = field.text
                                    if field.tag == 'cvss3_vector':
                                        vuln['cvss3Vector'] = field.text
                                newVulnerability = Vulnerability(**vuln)
                                vulnerabilities.append(newVulnerability)


        return endpoints.values(), vulnerabilities

                
    def get_all_scans(self) -> list[Scan]:
        scans = []
        data = self._nessus.scans.list()
        for scan in data['scans']:
            scan['folder_name'] = [folder['name'] for folder in data['folders'] if folder['id'] == scan['folder_id']][0]
            scans.append(Scan(**scan))
        return scans



'''
self._nessus.scans.list() results
{
   "folders":[
      {
         "unread_count":"None",
         "custom":0,
         "default_tag":0,
         "type":"trash",
         "name":"Trash",
         "id":2
      },
      {
         "unread_count":0,
         "custom":0,
         "default_tag":1,
         "type":"main",
         "name":"My Scans",
         "id":3
      }
   ],
   "scans":[
      {
         "folder_id":3,
         "type":"local",
         "read":true,
         "last_modification_date":1693587931,
         "creation_date":1695155430,
         "status":"completed",
         "uuid":"7c56a245-bccf-2865-8720-4defd90efd9d39a5b9ff5b9a2ca2",
         "shared":false,
         "user_permissions":128,
         "owner":"test",
         "timezone":"None",
         "rrules":"None",
         "starttime":"None",
         "enabled":false,
         "control":true,
         "live_results":1,
         "name":"Public IPs",
         "id":5
      }
    ],
   "timestamp":1695428749
}
'''           




'''
API
vulnerability
{
    "plugin_id": {integer},
    "plugin_name": {string},
    "plugin_family": {string},
    "count": {integer},
    "vuln_index": {integer},
    "severity_index": {integer}
}


host-details


host-vulnerability
{
    "host_id": {integer},
    "hostname": {string},
    "plugin_id": {integer},
    "plugin_name": {string},
    "plugin_family": {string},
    "count": {integer},
    "vuln_index": {integer},
    "severity_index": {integer},
    "severity": {integer}
}

plugin_details all fields
{'cvss_temporal_score', 'cvssV3_impactScore', 'thorough_tests', 'cvss_vector', 'cvss_base_score', 'always_run', 'threat_sources_last_28', 'dependency', 'xref', 'plugin_publication_date', 'fname', 'cve', 'usn', 'generated_plugin', 'threat_recency', 'plugin_modification_date', 'required_key', 'synopsis', 'plugin_name', 'asset_inventory_category', 'cvss3_base_score', 'vpr_score', 'iavb', 'threat_intensity_last_28', 'asset_inventory', 'cvss_score_source', 'script_version', 'exploitability_ease', 'exploit_available', 'product_coverage', 'description', 'iava', 'cvss3_temporal_vector', 'agent', 'excluded_key', 'exploit_framework_core', 'plugin_type', 'risk_factor', 'vuln_publication_date', 'potential_vulnerability', 'script_copyright', 'patch_publication_date', 'os_identification', 'cpe', 'required_port', 'solution', 'in_the_news', 'cea-id', 'cvss3_temporal_score', 'age_of_vuln', 'iavt', 'cvss_temporal_vector', 'exploit_code_maturity', 'see_also', 'cvss3_vector'}

'''



