from datetime import datetime, timedelta
import time
from openvasClient import OpenvasClient
import configparser
from loggingHelper import logger
import pynetbox
import ipaddress
import openvasParser
from report import Report
from repo import Repo
from sendEmail import send_email_report

config = configparser.ConfigParser()
config.read('openvas.conf')

openvas_username = config['openvas']['username']
openvas_password = config['openvas']['password']
scanConfigName = config['openvas']['scanConfigName']

emailFrom = config['email']['from']
emailTo = config['email']['to']
subject = config['email']['subject']
mailServer = config['email']['mailServer']

reportName = "vulnerabilities"
repo = Repo('vuln_management', "mongodb://mongo")

def main():

    while True:
        vulnerabilities = []
        endpoints = []
        startTimeScan = time.time()
        
        report = openvas_scanning(['localhost'])
        vulnerabilities = openvasParser.get_all_vulnerabilities(report,"Log")
        endpoints = openvasParser.get_all_endpoints(report)

        logger.info("Updating endpoints...")
        for endpoint in endpoints:
            update_endpoint(endpoint, repo)

        logger.info("Updating vulnerabilities...")
        for vulnerability in vulnerabilities:
            update_endpoint_vulnerability(vulnerability, repo)

        for endpoint in endpoints:
            update_endpoint_vulnerability_status(endpoint, vulnerabilities, repo)

        generate_spreadsheet_report(reportName)
        suffix = str(datetime.now().date()) 


        send_email_report(emailFrom, emailTo, f"{subject} - {suffix}", mailServer, reportName, reportName+'-'+suffix, 'xlsx')
        logger.info(f'Sending report {reportName}-{suffix}.xlsx to {emailTo}')

        logger.info(f'{len(vulnerabilities)} issues found')
        logger.info('Done')
        
        endTimeScan = time.time()
        timeTaken = int(endTimeScan - startTimeScan)
        sleepTime = int(config['openvas']['ScanInterval'])
        sleepFor = max(sleepTime - timeTaken, 0)
        logger.info(f"Scan finished, duration: {str(timedelta(seconds=timeTaken))}")
        logger.info(f"Waiting {str(timedelta(seconds=sleepFor))} for the next scan")
        time.sleep(sleepFor)

def update_endpoint_vulnerability_status(endpoint, vulnerabilities, repo):
    endpoint = repo.get_endpoint(endpoint.host, f"{endpoint.port}/{endpoint.protocol}")
    for oid in endpoint.oids.keys():
        endpointOidsReported = openvasParser.get_all_vulnerabilities_from_endpoint(vulnerabilities, endpoint)
        if oid not in endpointOidsReported and endpoint.oids[oid]['status'] == "Open":
            endpoint.oids[oid]['status'] = "Solved"
            endpoint.oids[oid]['solved_time'] = time.time()
            v = repo.find_vuln_by(oid)
            log_vuln("Solved endpoint vulnerability oid", endpoint, v)
        if oid in endpointOidsReported and endpoint.oids[oid]['status'] != "Open":
            endpoint.oids[oid]['status'] = "Open"
            v = repo.find_vuln_by(oid)
            log_vuln("Re-open endpoint vulnerability oid", endpoint, v)
            endpoint.oids[oid]['solved_time'] = ''
    repo.add_endpoint(endpoint)

def update_endpoint_vulnerability(vulnerability, repo):
    endpoint = repo.get_endpoint(vulnerability.host, vulnerability.portProtocol)
    if vulnerability._id not in endpoint.oids.keys():
        endpoint.add_oid(vulnerability._id)
        repo.add_endpoint(endpoint)
        repo.add_vulnerability(vulnerability)
        log_vuln("Added new endpoint vulnerability oid", endpoint, vulnerability)

def update_endpoint(endpoint, repo):
    result = repo.get_endpoint(endpoint.host, f"{endpoint.port}/{endpoint.protocol}")
    if not result:
        logger.info(f'Added new endpoint: {endpoint._id}')
        repo.add_endpoint(endpoint)
    


    result = repo.add_endpoint(endpoint)
    if result.upserted_id:
        logger.info(f'Added new endpoint: {endpoint._id}')
    # elif result.modified_count:
    #     logger.debug(endpoint)
    #     logger.info(f'Updated new endpoint: {endpoint._id}')

def openvas_scanning(hosts):
    gmp = OpenvasClient(openvas_username, openvas_password)  
    gmp.authenticate()
    logger.info('Updating system')
    #gmp.update()
    targetName = config['openvas']['targetName'] + ' ' + str(datetime.now())
    taskID = gmp.launch_scan(targetName=targetName, scanConfigName=scanConfigName, hosts=hosts)
    logger.info(f"Starting Scan {targetName}")
    gmp.wait_done(taskID, sleepTime=int(config['openvas']['checkScanInterval']))
    return gmp.get_report(taskID)

def generate_spreadsheet_report(reportName):    
    vulnerabilities = repo.get_summary()
    Report.toExcel(vulnerabilities, reportName)

def log_vuln(msg, endpoint, vulnerability):
    logger.info(f"{msg} oid:{vulnerability._id} threat:{vulnerability.threat} status:{endpoint.oids[vulnerability._id]['status']} endpoint:{endpoint._id}")

def get_netbox_ip(publicIP=True):

    nb = pynetbox.api(config['netbox']['url'], token=config['netbox']['token'])

    reqIps = nb.ipam.ip_addresses.filter(tenant=config['netbox']['tenant'])

    if publicIP:
        ips = [str(ip).split('/')[0] for ip in reqIps if not ipaddress.ip_address(str(ip).split('/')[0]).is_private]
    else:
        ips = [str(ip).split('/')[0] for ip in reqIps if ipaddress.ip_address(str(ip).split('/')[0]).is_private]

    logger.info(f'Scope: {len(ips)} IPs.')
    return ips

if __name__ == "__main__":
    main()
