from repo import Endpoint
from nessusParser import Scan


def test_scan():
    scan_dict =       {
         "folder_id":3,
         "type":"local",
         "read":True,
         "last_modification_date":1693587931,
         "creation_date":1695155430,
         "status":"completed",
         "uuid":"7c56a245-bccf-2865-8720-4defd90efd9d39a5b9ff5b9a2ca2",
         "shared":False,
         "user_permissions":128,
         "owner":"test",
         "timezone":"None",
         "rrules":"None",
         "starttime":"None",
         "enabled":False,
         "control":True,
         "live_results":1,
         "name":"Public IPs",
         "id":5,
         "folder_name":"test scan 1"
      }
    
    scan = Scan(**scan_dict)
    assert scan.folderNameNoSpaces() == "test_scan_1"
    assert scan.completed() == True
    print('test')



def test_endpoint():
    newVulnEndpoint = Endpoint(ip='1.1.1.1', port='8006', protocol='tcp', service='www', hostnames={'example.net', '.example.net'})
    newVulnEndpoint.add_vulnerability('123')
    newVulnEndpoint.add_vulnerability('12345')
    newVulnEndpoint.add_vulnerability('11111')

    oldVulnEndpoint = Endpoint(ip='1.1.1.1', port='8006', protocol='tcp', service='www', hostnames={'example.net', 'example.net'})

    oldVulnEndpoint.add_vulnerability('123')
    oldVulnEndpoint.add_vulnerability('1234')
    oldVulnEndpoint.add_vulnerability('12345')

    vulnAdded, vulnSolved = oldVulnEndpoint.update_vulnerabilities(newVulnEndpoint)

    assert vulnAdded == {'11111'}
    assert vulnSolved == {'1234'}

    oldVulnEndpoint.solve_vulnerability('123')

    assert oldVulnEndpoint.vulnerabilities['123']['status'] == "Solved"
    assert oldVulnEndpoint.vulnerabilities['1234']['status'] == "Solved"


def test_testing():
    assert 1==1