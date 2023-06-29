
from dataclasses import dataclass, field
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
import sys
from time import sleep
from loggingHelper import logger
import subprocess

@dataclass
class OpenvasClient:
    username: str
    password: str
    gmp: str = field(init=False)
    con: str = field(init=False)

    def authenticate(self):
        path = '/run/gvmd/gvmd.sock'
        connection = UnixSocketConnection(path=path)
        transform = EtreeCheckCommandTransform()
        self.con = Gmp(connection=connection, transform=transform)
        self.con.connect()
        self.gmp = self.con.determine_supported_gmp()
        self.gmp.authenticate(self.username, self.password)
        logger.info('Authentication Success')

    def re_authenticate(self):
        if not self.gmp.is_connected():
            self.gmp.connect()
            logger.info('Re-connecting to Openvas server')

    def update(self):
        subprocess.call(["gvm-feed-update"])

    def launch_scan(self, targetName, scanConfigName, hosts):
        self.target(targetName, hosts)
        return self.task(scanConfigName=scanConfigName, targetName=targetName)

    def wait_done(self, taskID, sleepTime=100):
        self.re_authenticate()
        status, progress, results = self.get_task_info(taskID)
        while status not in ['Done','Stopped'] :
            self.re_authenticate()
            logger.info(f'Status: {status} - Progress: {progress}% completed - results found: {results}')
            sleep(sleepTime)
            status, progress, results = self.get_task_info(taskID)

    def target(self, name, hosts):   
        try:
            self.gmp.create_target(name=name, hosts=hosts, port_list_id=self.get_id(self.gmp.get_port_lists, "port_list", "nmap"))    

        except GvmError as e:
            logger.error(f'[-] Error: {e}')

    def get_id(self, functionGet, elementName, name):
        element = functionGet(filter_string=name)
        return element.xpath(elementName)[0].get('id') 
    

    def task(self, scanConfigName, targetName):
        try:
            
            task = self.gmp.create_task(name=targetName, config_id=self.get_id(self.gmp.get_scan_configs, "config", scanConfigName)
                    , target_id=self.get_id(self.gmp.get_targets, "target", targetName)
                    , scanner_id=self.get_id(self.gmp.get_scanners, "scanner", "OpenVAS default"))

            self.gmp.start_task(task_id=task.get('id'))
            
            return task.get('id')

        except GvmError as e:
            logger.error(f'An error occurred {e}')

    def get_task_info(self, taskID):
        taskInfo = self.gmp.get_task(taskID).xpath('task')[0]
        progress = taskInfo.find('progress').text
        status = taskInfo.find('status').text
        results = taskInfo.find('result_count').text
        return status, progress, results

    def get_results(self, taskID):
        self.re_authenticate()
        reportID = self.gmp.get_task(taskID).xpath('task')[0].xpath('last_report')[0].find('report').get('id')
        report = self.gmp.get_report(reportID, ignore_pagination=True)
        results = []
        for result in report.xpath('report')[0].xpath('report')[0].xpath('results')[0]:
            if float(result.find('severity').text) > 0.0 :
                resultName = f"{result.find('host').text}:{result.find('port').text} - {result.find('name').text}"
                results.append(resultName)
                logger.info(f"[+] {resultName}")
        return results