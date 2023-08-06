from repo import Endpoint, Vulnerability


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

def get_all_endpoints(report):
    endpoints = []
    services = [service for service in report.findall('./report/report/results/result') if get_value(service, 'name') == "Services"]

    for host in [result for result in report.findall('./report/report/ports/port')]:
        newEndpoint = Endpoint(get_value(host,"host"),get_value_tail(host,"host"))
        update_service(newEndpoint, services)        
        endpoints.append(newEndpoint)
    return endpoints

    
def update_service(endpoint, services):
    for service in services:
        if endpoint == Endpoint(get_value(service,"host"),get_value(service,"port")):
            endpoint.service = get_value(service,"description")

def get_all_vulnerabilities_from_endpoint(vulnerabilitiesReported, endpoint):
    return [v._id for v in vulnerabilitiesReported if v.host == endpoint.host and v.portProtocol == f"{endpoint.port}/{endpoint.protocol}"]



