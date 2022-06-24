import subprocess
import re
import requests


def abuseipdb(ip: str, days: int):
    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }

    params = {
        'maxAgeInDays': days,
        'ipAddress': ip,
        'verbose': ''
    }

    r = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
    response = r.json()
    print(response)

    if response['data']['abuseConfidenceScore'] > 50:
        print(f'ip: {ip} is malicious')
    else:
        print(f'ip: {ip} is clean')
        

f = subprocess.Popen(['tail','-f','/var/log/snort/alert'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
follow = 0
while True:
    line = f.stdout.readline()
    line = line.decode()
    if line == '\n':
        follow = 0

    if line.startswith('[**]') and line.endswith('[**]\n'):
        title = line
        print(f'found title: {title.strip()}')
        if 'ICMP test' in title:
            follow = 1
        
    if follow:
        found_ip = re.findall(r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))', line)
        follow += 1
        if found_ip:
            print(f'found_ip: {found_ip}\n')
            follow = 0

            abuseipdb(found_ip[1], 30)
            break

    if follow > 10:
        print(f'fatal error!')
        break

