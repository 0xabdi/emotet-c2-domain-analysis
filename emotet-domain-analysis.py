#Author: Abdirahman Mohamed
#Date: March 2021
import whois
import socket
import robtex_python
import requests
import json
import urllib.request

#These domains were extracted by executing malicious emotet office docs in a sandbox environment and observing the C2 domain that they contacted.
#You can adapt this script to analyze C2 domains utilized by other Malwares by replacing the below domains and their resources.
domains = [
'isuzupoznan.pl',
'kanmoretail.com',
'colegiorosales.com',
'harboursidechurch.org',
'clever12.com',
'damchi.net',
'credibleinteriors.in',
'adserver.arcmediainteractive.com',
'ads-staging.planqk.com'
]

resources = [
    '/cNz1Rz/',
    '/lKhn5rc/',
    '/nihqiyo',
    '/YNgfxDP/',
    '/EcIF',
    '/hr8J',
    '/nxcPA',
    '/8YJAS1C',
    '/fKHzW',
    ]

print("-----------------------------------------------------------------------------------------------------------------")
print('{0: <15}'.format('#'), '{0: <25}'.format("Domain Name"), '{0: <15}'.format("Resource"), '{0: <15}'.format("Status Code"), '{0: <30}'.format("Creation Date"), '{0: <15}'.format("Country"))
print("-----------------------------------------------------------------------------------------------------------------")
 
i=1
j=0
for dom in domains:
    w = whois.whois(dom)
    ip = socket.gethostbyname(dom)
    res_url = "http://" + dom + resources[j]
    url_req = requests.get(res_url)
    status = url_req.status_code

    #response = robtex_python.pdns_forward(dom)
   
    if (type(w.domain_name).__name__ == 'str' and type(w.creation_date).__name__ == 'datetime'):
        print('{0: <15}'.format(i), '{0: <25}'.format(w.domain_name), '{0: <15}'.format(resources[j]), '{0: <15}'.format(status), '{0: <30}'.format(str(w.creation_date)), '{0: <15}'.format(str(w.country)))
    elif (type(w.domain_name).__name__ == 'str' and type(w.creation_date).__name__ == 'list'):
        print('{0: <15}'.format(i), '{0: <25}'.format(w.domain_name), '{0: <15}'.format(resources[j]), '{0: <15}'.format(status), '{0: <30}'.format(str(w.creation_date[0])), '{0: <15}'.format(str(w.country)))
    elif (type(w.domain_name).__name__ == 'list' and type(w.creation_date).__name__ == 'datetime'):
        print('{0: <15}'.format(i), '{0: <25}'.format(w.domain_name[0]), '{0: <15}'.format(resources[j]), '{0: <15}'.format(status), '{0: <30}'.format(str(w.creation_date)), '{0: <15}'.format(str(w.country)))        
    i+=1
    j+=1