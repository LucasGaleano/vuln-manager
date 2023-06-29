import sys
from datetime import datetime, timedelta
import time
import requests
import json
from openvasClient import OpenvasClient
import configparser
from loggingHelper import logger
import pynetbox
import ipaddress

config = configparser.ConfigParser()
config.read('openvas.conf')

openvas_username = config['openvas']['username']
openvas_password = config['openvas']['password']

alerta_url = config['alerta']['url']
alerta_api = config['alerta']['token']

def main():

    while True:
        startTimeScan = time.time()
        gmp = OpenvasClient(openvas_username, openvas_password)
        gmp.authenticate()
        logger.info('Updating system')
        gmp.update()
        targetName = config['openvas']['targetName'] + ' ' + str(datetime.now())
        taskID = gmp.launch_scan(targetName=targetName, scanConfigName=config['openvas']['scanConfigName'], hosts=get_netbox_ip())
        logger.info(f"Starting Scan {targetName}")
        gmp.wait_done(taskID, sleepTime=int(config['openvas']['checkScanInterval']))
        results = gmp.get_results(taskID)

        #send_alerta(results)
        logger.info(f'{len(results)} issues found') 
        logger.info('Done')
        print(results)
        
        endTimeScan = time.time()
        timeTaken = int(endTimeScan - startTimeScan)
        sleepTime = int(config['openvas']['ScanInterval'])
        sleepFor = max(sleepTime - timeTaken, 0)
        logger.info(f"Scan finished, duration: {str(timedelta(seconds=timeTaken))}")
        logger.info(f"Waiting {str(timedelta(seconds=sleepFor))} for the next scan")
        time.sleep(sleepFor)


def get_netbox_ip(publicIP=True):

    nb = pynetbox.api(config['netbox']['url'], token=config['netbox']['token'])

    reqIps = nb.ipam.ip_addresses.filter(tenant=config['netbox']['tenant'])

    if publicIP:
        ips = [str(ip).split('/')[0] for ip in reqIps if not ipaddress.ip_address(str(ip).split('/')[0]).is_private]
    else:
        ips = [str(ip).split('/')[0] for ip in reqIps if ipaddress.ip_address(str(ip).split('/')[0]).is_private]

    logger.info(f'Scope: {", ".join(ips)}')
    return ips




def send_alerta(results):
    headers = {'content-type': 'application/json'}
    params = {'api-key': alerta_api}

    data = {
            "environment": "Security",
            "event": f"{len(results)} issues found",
            "origin": "External Penetration Test",
            "resource": "External Penetration Test",
            "service": [
                       "External Penetration Test"
                           ],
            "severity": "critical",
            "text": "Results from the external penetration test.",
            "rawData" : '\n'.join(results)
            }

    response = requests.post(alerta_url, data=json.dumps(data), headers=headers, params=params)
    logger.info(f'[+] Sending results to Alerta {response}')

if __name__ == "__main__":
    main()
