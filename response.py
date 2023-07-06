import json
import re

import telepot
from thehive4py.api import TheHiveApi
from thehive4py.query import Eq
from thehive4py.models import Case

# from thehive4py.exceptions import CaseException, CaseObservableException


def tag_person(client, caseStatus):  # Определяем кого нужно тегнуть в телеграме
    if caseStatus == 'TruePositive':
        if client.lower()[:3] in ['client_name']:
            return 'responsible_person'
        elif client.lower()[:3] in ['client_name']:
            return 'responsible_person'
    elif caseStatus == 'Indeterminate':
        if client.lower()[:3] in ['client_name']:
            return 'responsible_person'
        elif client.lower()[:3] in ['client_name']:
            return 'responsible_person'


def write_txt(client, address):  # Записываем IP адреса в файлы без их дублирования
    abbr = {
        'client_name': 'client.txt',
    }
    try:
        with open(abbr[client], 'x') as file:  # Создаем файл если его не существует
            pass
    except FileExistsError:
        pass
    with open(abbr[client], 'r') as file:
        for ip_address in file.read().splitlines():  # Смотрим есть ли уже такой адрес в файле
            if ip_address == address:
                break
        else:
            with open(abbr[client], 'a') as file:  # Если его нет то записываем
                file.write(f'{address}\n')





api = TheHiveApi('the_hive_ip_addr', 'the_hive_api_key')
token = 'tg_bot_token'
bot = telepot.Bot(token)
chats = {"TruePositive":"certain_chat", "Indeterminate":"certain_chat"}

for key, value in chats.items():
    tag = 'TruePositive'
    if key == 'Indeterminate':
        tag = 'ESCALATING'


    query = Eq('status', key)
    cases = api.find_cases(query=query, sort=['-startDate'], range='all').json()  # Сортируем по дате и берем 30 кейсов
    
    for _case in cases:
        if 'SENT' in _case['tags'] or 'ESCALATING' in _case['tags'] and _case['extendedStatus'] == 'Indeterminate': # Если кейс (отправлен/без тэга), то не обрабатываем его
            continue

        observable = api.get_case_observables(_case['id']).json()
        if len(observable) == 0 or observable[0].get('reports') == {}:  # Если нет Observables или он не запущен:
            bot.sendMessage(value, f'Client: {_case["tags"][0]}\n' \
                                                 f'Title: {_case["title"]}\n' \
                                                 f'Case number: {_case["caseId"]}\n' \
                                                 'Message:\n' + _case["summary"].strip("\n") + '\n\n' \
                                                 f'{tag_person(_case["tags"][0], key)}')
        else:
            if _case['tags'][0].lower()[:3] in ['certain_client_name']:  # Если отправляем репорт Адилю то записываем в файл
                write_txt(_case['tags'][0].lower()[:3], observable[0]["data"])
            else:
                print(observable)
                # Отправка репорта в телеграм группу
                ips = []
                counterTrue = 0
                counterFalse = 0

                linked = api.get_linked_cases(_case['id']).json()
                data = dict(re.findall(r'(\w+)=([^\t]+)', str(observable[0]["reports"]["IPinfo_Details_1_0"]["taxonomies"][0]["value"])))
                for index, i in enumerate(observable):
                    for l in linked:
                        if i["data"] == l['linkedWith'][0]['data']:
                            if l['extendedStatus'] == "TruePositive":
                                counterTrue += 1
                            elif l['extendedStatus'] == "FalsePositive":
                                counterFalse += 1
                    relatedCases = f'True Positive: {counterTrue}\nFalse Positive: {counterFalse}'
                    ips.append(f'{i["data"]} - AbuseIPDB: {i["reports"]["AbuseIPDB_1_0"]["taxonomies"][0]["value"]}, OTXQuery: {i["reports"]["OTXQuery_2_0"]["taxonomies"][0]["value"]}\nCountry : {data["Country"]}, Vendor: {data["Org"]}\nRelated Cases: \n{relatedCases}\n')
                    counterTrue = 0
                    counterFalse = 0
                message = '\n'.join(ips)
                bot.sendMessage(value, f'Client: {_case["tags"][0]}\n' \
                                             f'Title: {_case["title"]}\n' \
                                             f'Case number: {_case["caseId"]}\n\n' \
                                             f'IP address:\n {message}\n' \
                                             '\nMessage:\n' + _case["summary"].strip("\n") + '\n\n' \
                                             f'{tag_person(_case["tags"][0], key)}')



        new_case = api.case(_case['id'])
        new_case.tags.append(tag)  # Помечаем кейс отправленным
        new_case.status = key
        api.update_case(new_case)


