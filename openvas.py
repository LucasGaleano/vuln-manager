from datetime import datetime, timedelta
import time
from openvasClient import OpenvasClient
import configparser
from loggingHelper import logger
import pynetbox
import ipaddress
from openvasParser import update_database
from report import Report
from repo import Repo

config = configparser.ConfigParser()
config.read('openvas.conf')

openvas_username = config['openvas']['username']
openvas_password = config['openvas']['password']

alerta_url = config['alerta']['url']
alerta_api = config['alerta']['token']

reportName = "vulnerabilities"
repo = Repo('vuln_management', "mongodb://mongo")

def main():

    while True:
        startTimeScan = time.time()
        gmp = OpenvasClient(openvas_username, openvas_password)
        gmp.authenticate()
        logger.info('Updating system')
        #gmp.update()
        targetName = config['openvas']['targetName'] + ' ' + str(datetime.now())
        taskID = gmp.launch_scan(targetName=targetName, scanConfigName=config['openvas']['scanConfigName'], hosts=['localhost'])
        logger.info(f"Starting Scan {targetName}")
        gmp.wait_done(taskID, sleepTime=int(config['openvas']['checkScanInterval']))
        report = gmp.get_report(taskID)

        update_database(repo, report)
        generate_spreadsheet_report(reportName)
        results = gmp.get_results(taskID)

        logger.info(f'{len(results)} issues found') 
        logger.info('Done')
        
        endTimeScan = time.time()
        timeTaken = int(endTimeScan - startTimeScan)
        sleepTime = int(config['openvas']['ScanInterval'])
        sleepFor = max(sleepTime - timeTaken, 0)
        logger.info(f"Scan finished, duration: {str(timedelta(seconds=timeTaken))}")
        logger.info(f"Waiting {str(timedelta(seconds=sleepFor))} for the next scan")
        time.sleep(sleepFor)

def generate_spreadsheet_report(reportName):    
    vulnerabilities = repo.get_summary()
    Report.toExcel(vulnerabilities, reportName)


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
