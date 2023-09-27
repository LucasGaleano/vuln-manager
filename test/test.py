from repo import Endpoint


def test_endpoint():
    newVulnEndpoint = Endpoint(ip='1.1.1.1', port='8006', protocol='tcp', service='www', hostnames={'example.net', '.example.net'}, vulnerabilities={'123': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}, '12345': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}, '11111': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}})

    oldVulnEndpoint = Endpoint(ip='1.1.1.1', port='8006', protocol='tcp', service='www', hostnames={'example.net', 'example.net'}, vulnerabilities={'123': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}, '1234': {'status': 'Open', 'notes': '', 'finding_time': '1695236077', 'solved_time': ''}, '123456': {'status': 'Open', 'notes': '', 'finding_time': '1695236077'}})

    vulnAdded, vulnSolved = oldVulnEndpoint.update_vulnerabilities(newVulnEndpoint)

    assert vulnAdded == {123}
    assert vulnSolved == {1234}


def test_testing():
    assert 1==1