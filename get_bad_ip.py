import requests
import re

def get_bad_ip():
    resp = requests.get('https://isc.sans.edu/api/threatlist')
    data = resp.text
    bad_ip_list = re.findall(r'<ipv4>(.+?)</ipv4>', data)
    return bad_ip_list
    
data = get_bad_ip()
for ip in data:
    print(ip)

def print_ip_data():
    for ip in data:
        resp = requests.get('https://isc.sans.edu/api/ip/{}'.format(ip))
        print(resp.text)