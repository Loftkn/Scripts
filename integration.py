#!/bin/bash

import json
import re
from thehive4py.exceptions import CaseException, CaseObservableException
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable
import requests
from datetime import datetime, timedelta
import time

def get_alerts(last_hours, size, client_name, client_ip) -> dict:
    # Две переменные чтобы указать интервал времени необходимых инцидентов
    # last_hours=2, size=3  -> Берет 3 инцидента за последние 2 часа
    gte = (datetime.now() - timedelta(hours=last_hours + 6)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'
    lte = (datetime.now() - timedelta(hours=6)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'

    json_data = {
        "aggs": {
            "alertsByGrouping": {
                "terms": {
                    "field": "signal.rule.name",
                    "order": {
                        "_count": "desc"
                    },
                    "size": 10
                }
            }
        },
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "must": [],
                            "filter": [
                                {
                                    "term": {
                                        "signal.status": "open"
                                    }
                                }
                            ],
                            "should": [],
                            "must_not": [
                                {
                                    "exists": {
                                        "field": "signal.rule.building_block_type"
                                    }
                                }
                            ]
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
        },
        'size': size
    }
    data = {}
    r = requests.post(f'https://{client_ip}/api/detection_engine/signals/search', headers=headers, json=json_data,
                      verify=False).json()

    for i in r['hits']['hits']:
        if client_name != "Proda":
            index = client_name.upper()
        else:
            index = str(i['_source']['signal']['parent'].get('index', 'Unknown')).split("-")
            if index[1] == "*":
                index = index[0].upper()
            else:
                index = index[1].upper()

        if str(i['_source']['signal']['rule']['type']) == 'threshold' and 'Rule name(user checker)' in str(i['_source']['signal']['rule']['name']):
            data[i['_id']] = {
                    'type': 'thresholdUser',
                    'index': index,
                    'name': i['_source']['signal']['rule']['name'],
                    'username': i['_source']['username.keyword'],
                    'count': i['_source']['signal']['threshold_result']['cardinality'][0]['value']
                }
        elif str(i['_source']['signal']['rule']['type']) == 'query': #Условие обрабатывающее только custom query правила
            data[i['_id']] = {
                    'type': i['_source']['signal']['rule'].get('type', 'Unknown'),
                    'index': index,
                    'name': i['_source']['signal']['rule'].get('name', 'Unknown'),
                    'ip': i['_source'].get('source.address', i['_source'].get('source', {}).get('address', i['_source'].get('source', {}).get('ip', i['_source'].get('related', {}).get('ip')))),
                    'log': i['_source'].get('message', i['_source'].get('event', {}).get('original', i['_source']['signal'].get('original_event', {}).get('original', i.get('_source'))))
            }
        else:
            data[i['_id']] = {
                    'type': i['_source']['signal']['rule'].get('type', 'Unknown'),
                    'index': index,
                    'name': i['_source']['signal']['rule'].get('name', 'Unknown'),
                    'ip': i['_source'].get('source.address', i['_source'].get('source', {}).get('address', i['_source'].get('source', {}).get('ip', i['_source'].get('related', {}).get('ip')))),
                    'log': i['_source'].get('message', i['_source'].get('event', {}).get('original', i['_source']['signal'].get('original_event', {}).get('original', i.get('_source'))))
            }
        close_alert(i['_id'], client_ip)
    return data


def close_alert(alert_id, client_ip) -> None:  # Помечает инцидент закрытым в Kibana во вкладке security#alerts
    json_data = {
        'status': 'closed',
        'query': {
            'bool': {
                'filter': {
                    'terms': {
                        '_id': [alert_id],
                    },
                },
            },
        },
    }

    r = requests.post(f'https://{client_ip}/api/detection_engine/signals/status',
                  headers=headers, json=json_data, verify=False)

#Указываем клиента-версию кибаны: ip адрес где находится кибана с портом - api ключ
clients = {'Client-kbn_ver': "kibana_ip_addr-apiKey", "Proda-kbn_version": "kibana_ip_addr:port-apiKey"}

for key, value in clients.items():
    key = key.split("-")
    value = value.split("-")
    unique_alerts = {}
    headers = {
        'Content-Type': 'application/json',
        'Host': value[0],
        'kbn-version': key[1],
        'Authorization': f'Apikey {value[1]}',
        'Connection': 'close'
    }
    alerts = get_alerts(last_hours=2, size=20, client_name=key[0], client_ip=value[0])
    api = TheHiveApi('http://thehive_ip_addr:9000', 'apiKey')

    # Создаем Case+CaseObservable на каждый инцидент собранный из функции get_alerts
    for alert in alerts.values():
        if alert['type'] == 'thresholdUser':
            message = alert["username"] + 'description from rule' + '\n\n' + 'Threshold Cardinality count(source.address.keyword) == ' + str(alert['count'])
            case_ = Case(title=alert['name'],
                         tags=[alert['index']],
                         description=message)
        
        elif alert['type'] == 'query':
            if alert['name'] in unique_alerts.keys() and alert['log'] in unique_alerts.values():
                if list(unique_alerts.keys()).index(alert['name']) == list(unique_alerts.values()).index(alert['log']):
                    continue
            else:
                unique_alerts[alert['name']] = alert['log']
                case_ = Case(title=alert['name'],
                          tags=[alert['index'], alert.get('ip')],
                          description=f'{alert["log"]}')
        
        response = api.create_case(case_).json() #Создание кейса и уникальный case_id
        case_id = response['id']
        if alert.get('ip'): #Если у кейса есть IP то создаем observable
            observable = CaseObservable(dataType='ip',
                                        data=alert['ip'],
                                        ioc=True,
                                        tags=[alert['index']],
                                        message=alert['log']
                                        )
            api.create_case_observable(case_id, observable)
