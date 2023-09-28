from datetime import datetime, timedelta
import time
import json
from nessusParser import NessusParser, Scan
import configparser
from loggingHelper import logger
from report import Report
from repo import Repo, Endpoint, Vulnerability
from sendEmail import send_email_report

config = configparser.ConfigParser()
config.read('manager.conf')


nessus = NessusParser(config['nessus']['url'],
                      config['nessus']['port'],
                      config['nessus']['access_key'],
                      config['nessus']['secret_key'])

emailFrom = config['email']['from']
emailTo = config['email']['to']
subject = config['email']['subject']
mailServer = config['email']['mailServer']

ddbb_user = config['ddbb']['user']
ddbb_password = config['ddbb']['password']


reportName = "vulnerabilities"

def main():

    scans_updated = {}

    while True:
        
        nessus.connect()

        scans = nessus.get_all_scans()
        for scan in scans:

            databaseName =  scan.folderNameNoSpaces()

            if not scan.completed():
                logger.info(f"Scan not finished folder: {databaseName} name: {scan.name}")
                continue
                    
            with Repo(databaseName, host="mongo", user=ddbb_user, password=ddbb_password) as repo:

                logger.info(f"Fetching report {databaseName} name: {scan.name}")

                try:
                    endpoints, vulnerabilities = nessus.scan_export_request(scan.id)

                    logger.info("Updating vulnerabilities...")
                    for vulnerability in vulnerabilities:
                        update_vulnerability(repo, vulnerability)
                    logger.info("Vulnerabilities updated")

                    logger.info("Updating endpoints...")
                    for endpoint in endpoints:
                        update_endpoint(repo, endpoint)
                    logger.info("Endpoints updated")

                    # generate_spreadsheet_report(reportName)
                    # suffix = str(datetime.now().date()) 


                    # send_email_report(emailFrom, emailTo, f"{subject} - {suffix}", mailServer, reportName, reportName+'-'+suffix, 'xlsx')
                    # logger.info(f'Sending report {reportName}-{suffix}.xlsx to {emailTo}')

                    if not is_scan_parser_previously(scan, scans_updated):
                        log_summary(vulnerabilities, scan, repo)

                    logger.info('Done')
                
                except Exception as e:
                    print(f"Error fetching {databaseName} name: {scan.name}: {e}")
        
        sleepTime = int(config['nessus']['checkScanInterval'])
        logger.info(f"Waiting {str(timedelta(seconds=sleepTime))} for the next scan")
        time.sleep(sleepTime)

def log_summary(vulnerabilities: list[Vulnerability], scan: Scan, repo: Repo):
    logOutput = {}
    logOutput['msg'] = 'Results summary'
    countVuln = [v.threat for v in vulnerabilities]
    logOutput['critical'] = countVuln.count('Critical')
    logOutput['High'] = countVuln.count('High')
    logOutput['Medium'] = countVuln.count('Medium')
    logOutput['Low'] = countVuln.count('Low')
    logOutput['assessment'] = repo.databaseName
    logOutput['scan'] = scan.name
    logOutput['table_format'] = f"{logOutput['msg']}\nassessment: {logOutput['assessment']}\nscan: {logOutput['scan']}\ncritical: {logOutput['critical']}\nHigh: {logOutput['High']}\nMedium: {logOutput['Medium']}\nLow: {logOutput['Low']}\n"
                                
    logger.info(json.dumps(logOutput))


def is_scan_parser_previously(scan: Scan, scans_updated: dict):
    if scan.id in scans_updated:
        if scans_updated[scan.id] == scan.last_modification_date:
            return True
        
    scans_updated[scan.id] = scan.last_modification_date
    return False

def update_vulnerability(repo: Repo, vulnerability: Vulnerability):
    result = repo.add_vulnerability(vulnerability)
    if not result.matched_count:
        log_vuln("Added vulnerability to ddbb", vulnerability, repo=repo)


def update_endpoint(repo: Repo, endpoint: Endpoint):
    fetchEndpoint = repo.get_endpoint_by_id(endpoint._id)
    if not fetchEndpoint:
        log_endpoint('Added endpoint',endpoint, repo)
        repo.add_endpoint(endpoint)
        for vulnID in endpoint.vulnerabilities.keys():
            vuln = repo.find_vuln_by_id(vulnID)
            log_vuln("Added vulnerability",vuln, endpoint, repo)

    if fetchEndpoint:
        vulnAdded, vulnSolved = fetchEndpoint.update_vulnerabilities(endpoint)
        for vulnID in vulnAdded:
            vuln = repo.find_vuln_by_id(vulnID)
            log_vuln("Added vulnerability:",vuln, fetchEndpoint, repo)
        for vulnID in vulnSolved:
            vuln = repo.find_vuln_by_id(vulnID)
            log_vuln("Solved vulnerability:",vuln, fetchEndpoint, repo)
        repo.add_endpoint(fetchEndpoint)


# def generate_spreadsheet_report(reportName):    
#     vulnerabilities = repo.get_summary()
#     Report.toExcel(vulnerabilities, reportName)

def log_vuln(msg, vulnerability, endpoint: Endpoint=None, repo: Repo=None):
    logOutput = vulnerability.json()
    if endpoint:
        logOutput['ip'] = endpoint.ip
        logOutput['port'] = endpoint.port
        logOutput['protocol'] = endpoint.protocol
        logOutput['status'] = endpoint.vulnerabilities[vulnerability._id]['status']
    if repo:
        logOutput['assessment'] = repo.databaseName
    logOutput['id'] = logOutput['_id']
    del logOutput['_id']
    logOutput['description']
    logOutput['msg'] = msg
    logger.info(json.dumps(logOutput))


def log_endpoint(msg, endpoint, repo: Repo):
    logOutput = endpoint.json()
    logOutput['msg'] = msg
    del logOutput['vulnerabilities']
    logOutput['assessment'] = repo.databaseName
    logger.info(json.dumps(logOutput))

# def get_netbox_ip(publicIP=True):

#     nb = pynetbox.api(config['netbox']['url'], token=config['netbox']['token'])

#     reqIps = nb.ipam.ip_addresses.filter(tenant=config['netbox']['tenant'])

#     if publicIP:
#         ips = [str(ip).split('/')[0] for ip in reqIps if not ipaddress.ip_address(str(ip).split('/')[0]).is_private]
#     else:
#         ips = [str(ip).split('/')[0] for ip in reqIps if ipaddress.ip_address(str(ip).split('/')[0]).is_private]

#     logger.info(f'Scope: {len(ips)} IPs.')
#     return ips

if __name__ == "__main__":
    main()
