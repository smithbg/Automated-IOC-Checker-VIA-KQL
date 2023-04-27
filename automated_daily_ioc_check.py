import requests
import json
import urllib3
from constants import Bearer_URL, query_URL, client_id, client_secret
import alert_email
from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime


def threatfox_query_recent_iocs():
    """This fuctions pulls of list of Indicators of compormise(IOC) and adds them to a file called iocs.txt one iocs for each line. This fuction then calls ioc_query()
    in order to form the KQL query

        EXAMPLE OF IOC.TXT:
            128.106.194.222:445
            104.237.11.5:445
            94.177.123.109:445
    """
    
    pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50)
    data = {
        'query':    'get_iocs',
        'days':     1
    }
    json_data = json.dumps(data)

    response = pool.request("POST", "/api/v1/", body=json_data)
    response = response.data.decode("utf-8")
    jsun = json.loads(response)

    f = open("iocs.txt", "w")
    for i in range(len(jsun["data"])):
        f.write(jsun["data"][i]["ioc"]+'\n')
    f.close()
    ioc_query()

def ioc_query():
    '''This fuction read all the IOCS that are in ioc.text and puts them into KQL query form. This file then calls
    Bearer() to start the api process
    
        EXAMPLE QUERY:
            Event | where EventData contains "128.106.194.222:445" or EventData contains "104.237.11.5:445" or EventData contains "94.177.123.109:445"
   
     '''

    file_path = "iocs.txt"

    with open(file_path, "r") as file:
        line_count = 0
        for line in file:
            line_count += 1

    with open(file_path, "r") as file:
        text = ""
        for i in range(line_count):
            if i == line_count -1 :
                line = file.readline()
                no_new_line = line.replace("\n", "")
                text += "EventData contains " +'"'+ no_new_line +'"'
            else:
                line = file.readline()
                no_new_line = line.replace("\n", "")
                text += "EventData contains " +'"'+ no_new_line +'"'+ " or "

    f = open("kql.txt", "w")
    f.write("Event | where "+text)
    f.close()
    bearer()



def bearer():
    """This file creates a  """

    url = Bearer_URL

    payload = 'grant_type=client_credentials&client_id='+ client_id+'&resource=https%3A%2F%2Fapi.loganalytics.io&client_secret='+client_secret
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': 'buid=0.AVAAyJTMS0MtWkq6ovJatAsIaM1zg0_EbGJFvzzOgVwKxwN_AAA.AQABAAEAAAD--DLA3VO7QrddgJg7WevrIflKBadkfeCBTQWWBw8WSOFOGkkvUJajLMHePN_UX73jx2aswV_9cO7Mw_AO6FG2n257FEIRMIcZ_9lnlRgHwgU22wXCw17q0iKsbBxT6DwgAA; esctx=PAQABAAEAAAD--DLA3VO7QrddgJg7WevrIFtdP-ri2p2nbtjFO-hB9e2HhcLCLK79FfiJEvKWBxobMg5Fj-p57AiAVulolMtg0C1-J_IX3OYImGCuFcNxyb-KIhTZvkgXrNuID1jkCK7f6xNTeuJIwRxllE6qqtzbR04XOrnKn0fYQZy1ulpo_EWes5eABdM4b198rGnfcqEvLkJMeMfhjCqf_uqwcbwKpqneCm1VwdbtTGBUSL9qo1H-1cI6XkhDFZV2ta66sAcgAA; fpc=AnD_EJOnCBRPkKISPuqEXsE1zGsgAQAAAFNC2dsOAAAA; stsservicecookie=estsfd; x-ms-gateway-slice=estsfd'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    jsun = json.loads(response.text)
    token = jsun["access_token"] 
    req(token)

def req(token):
    with open('kql.txt', 'r') as file:
        qurey = file.read() 
    url = query_URL + qurey

    payload = {}
    headers = {
    'Authorization': 'Bearer ' + token 
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    jsun = json.loads(response.text)
    results = jsun["tables"][0]["rows"]
    if len(results) == 0:
        alert_email.No_findings_email_notify()
    else:
        alert_email.findings_email_notify()

    print("sucsses")



scheduler = BlockingScheduler()

scheduler.add_job(threatfox_query_recent_iocs, 'cron', hour=9)

scheduler.start()