from loggingHelper import logger
from repo import Repo, Endpoint, Vulnerability



# docker run -d --rm -p 27017:27017 --name mongo mongo:4.4.23  


def get_value(element, tag):
    try:
        return element.findall(tag)[0].text.strip()
    except:
        return ""
    
def get_value_tail(element, tag):
    try:
        return element.findall(tag)[0].tail.strip()
    except:
        return ""

def get_value_head(element, tag):
    try:
        return element.findall(tag)[0].head.strip()
    except:
        return ""

def get_all_vulnerabilities(report, minThreat):
    vulnerabilities = []
    for vulnResult in [result for result in report.findall('./report/report/results/result') if get_value(result,"threat") != minThreat]:
        nvt = vulnResult.findall('nvt')[0]
        vulnerability = Vulnerability(_id=nvt.get("oid"),
                                      name=get_value(nvt, 'name'),
                                      family=get_value(nvt, 'family'),
                                      threat=get_value(vulnResult, 'threat'),
                                      cvss=get_value(nvt, 'severities/severity/score'),
                                      date=get_value(nvt, 'severities/severity/date'),
                                      value=get_value(nvt, 'severities/severity/value'),
                                      solution=get_value(vulnResult, 'solution'),
                                      description=get_value(vulnResult, 'description'),
                                      host=get_value(vulnResult,'host'),
                                      portProtocol=get_value(vulnResult,'port'))
        vulnerabilities.append(vulnerability)
    
    return vulnerabilities

    
def get_all_vulnerabilities_from_endpoint(vulnerabilitiesReported, endpoint):
    return [v._id for v in vulnerabilitiesReported if v.host == endpoint.host and v.portProtocol == f"{endpoint.port}/{endpoint.protocol}"]

def update_host(report,repo):
    logger.info("Updating hosts...")
    for host in [result for result in report.findall('./report/report/ports/port')]:
        newEndpoint = Endpoint(get_value(host,"host"),get_value_tail(host,"host"))
        result = repo.add_endpoint(newEndpoint)
        if result.upserted_id:
            logger.info(f'Added new endpoint: {newEndpoint._id}')
        elif result.modified_count:
            logger.debug(newEndpoint)
            logger.info(f'Updated new endpoint: {newEndpoint._id}')

def update_service(report,repo):
    logger.info("Updating services...")
    for services in [result for result in report.findall('./report/report/results/result')]:
        if get_value(services, 'name') == "Services":
            endpoint = Endpoint(get_value(services,"host"),get_value(services,"port"),service=get_value(services,"description"))
            logger.debug(endpoint)
            repo.add_endpoint(endpoint)


def update_database(repo, report):
    
    update_host(report, repo)
    update_service(report, repo)

    vulnerabilitiesReported = []

    for vulnerability in get_all_vulnerabilities(report, 'Log'):
        vulnerabilitiesReported.append(vulnerability)
        endpoint = repo.get_endpoint(vulnerability.host, vulnerability.portProtocol)
        if vulnerability._id not in endpoint.oids.keys():
            endpoint.add_oid(vulnerability._id)
            repo.add_endpoint(endpoint)
            repo.add_vulnerability(vulnerability)
            logger.info(f"Added new endpoint vulnerability oid:{vulnerability._id} threat:{vulnerability.threat} status:{endpoint.oids[vulnerability._id]['status']} endpoint:{endpoint._id}")


    for host in [result for result in report.findall('./report/report/ports/port')]:
        endpoint = repo.get_endpoint(get_value(host,"host"),get_value_tail(host,"host"))
        for oid in endpoint.oids.keys():
            if oid not in get_all_vulnerabilities_from_endpoint(vulnerabilitiesReported, endpoint) and endpoint.oids[oid]['status'] != "Solved":
                endpoint.oids[oid]['status'] = "Solved"
                v = repo.find_vuln_by(oid)
                logger.info(f"Added new endpoint vulnerability oid:{oid} threat:{v['threat']} status:{endpoint.oids[oid]['status']} endpoint:{endpoint._id}")
            else:
                endpoint.oids[oid]['status'] = "Open"
            repo.add_endpoint(endpoint)


