from elasticsearch8 import Elasticsearch
import urllib3
import certifi
from datetime import datetime, date, timedelta
import json
import thehive4py
from thehive4py.api import TheHiveApi
from thehive4py.models import CaseTask, CaseObservable
from thehive4py.query import *
urllib3.disable_warnings()
import requests
from datetime import datetime, timedelta
import ipaddress
import time

def check_users(username):
    gte = (datetime.now() - timedelta(hours=2 + 6)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'
    lte = (datetime.now() - timedelta(hours=6)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'

    query = {"query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "filter": [
                                    {
                                        "term": {
                                            "username": username
                                        }
                                    }
                                ],
                            }
                        },
                        {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte
                            }
                        }
                    }
                ]
            }
        }
    }
    ip_list = []
    indexMatch = es.search(index="index", body=query, size ='200')
    for i in indexMatch['hits']['hits']:
        ip_list.append(i['_source']['source']['address'])
    return set(ip_list)

def get_netmask(case_id, observable_id, analyzer_id):
    headers = {
        'Authorization': 'Bearer apiKey',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/json',
        'Origin': 'http://the_hive_ip_addr',
        'Connection': 'keep-alive',
        'Referer': f'http://thehive_ip_addr/cases/{case_id}/observables/{observable_id}',
    }

    params = {
        'name': f'get-observable-report-{analyzer_id}',
    }
    json_data = {
        'query': [
            {
                '_name': 'getJob',
                'idOrName': f'{analyzer_id}',
            },
            {
            '_name': 'page',
            'from': 0,
            'to': 1,
            'extraData': [
                'report',
            ],
            },
        ],
    }


    response = requests.post('http://the_hive_ip_addr/api/v1/query', params=params, headers=headers, json=json_data).json()
    print(response[0]['extraData']['report']['full']['attributes']['network'])
    return response[0]['extraData']['report']['full']['attributes']['network']

def remove_duplicate_subnets(ips, obs):
    unique_subnets = {}
    for i, ip_str in enumerate(ips):
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            continue
        subnet = ipaddress.ip_network((obs[i]))
        if subnet not in unique_subnets:
            unique_subnets[subnet] = ip
    unique_ips = set(unique_subnets.values())
    return unique_ips

def run_analyzers(api, observable_id):
    analyzers = ['IPinfo_Details_1_0', 'AbuseIPDB_1_0', 'MISP_2_1', 'OTXQuery_2_0', 'VirusTotal_GetReport_3_1']
    id_Virustotal = []
    for i in analyzers:
        response = api.run_analyzer('cortex0', observable_id, i)
        if response.json()['analyzerName'] == 'VirusTotal_GetReport_3_1':
            id_Virustotal.append(response.json()['id'])
    return id_Virustotal

es = Elasticsearch([{'host':'elastic/kibana_ip_addr', 'scheme':'https', 'port':9200}], verify_certs=False, basic_auth=('user', 'passwd'))      
es.indices.refresh(index="index")
api = TheHiveApi('the_hive_ip_addr', 'the_hive_apiKey')

query = Eq('status', 'New')
cases = api.find_cases(query=query, sort=['-startDate'], range='all').json()

for _case in cases:
    if 'AUTO' in _case['tags']:
        username = _case['tags'][1]
        ip_addresses = list(check_users(username))
        non_private_ips = []
        obs = []
        try:
            for i in ip_addresses:
                if ipaddress.ip_address(i).is_private:
                    continue
                non_private_ips.append(i)
                observable = CaseObservable(dataType='ip',
                                        data=i,
                                        ioc=True,
                                        description=username
                                        )
                resp = api.create_case_observable(_case['id'], observable)
                analyzer_id = run_analyzers(api, resp.json()[0]['id'])
                time.sleep(3)
                obs.append(get_netmask(_case['id'], resp.json()[0]['id'], analyzer_id[0]))
        except Exception as e:
            close_case = api.case(_case['id'])
            close_case.tags = [close_case.tags[0], close_case.tags[1]]
            close_case.status = 'New'
            response = api.update_case(close_case)
            exit()
        ips_total = [str(i) for i in remove_duplicate_subnets(non_private_ips, obs)]
        observables = api.get_case_observables(_case['id']).json()
        observables_to_remove = []
        for observable in observables:
            if observable.get('dataType') == 'ip':
                if observable.get('data') not in ips_total:
                    api.delete_case_observable(observable['id'])      
        all_ips = '\n'.join(ips_total)
        if len(ips_total) >= 4:
            close_case = api.case(_case['id'])
            close_case.tags.append('Processed')
            close_case.status = 'TruePositive'
            close_case.summary = f'{username}\n{all_ips}'
            api.update_case(close_case)
        else:
            close_case = api.case(_case['id'])
            close_case.tags.append('Processed')
            close_case.status = 'FalsePositive'
            close_case.summary = f'{username}\nonly {len(ips_total)} ip addresses:\n{all_ips}'
            api.update_case(close_case)
    else:
        continue
