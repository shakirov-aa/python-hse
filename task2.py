import requests

API_URL = 'https://vulners.com/api/v3/burp/softwareapi/'
API_KEY = 'DE6UMMHEFJOVOTQ1B7WYWIJ21YX34ASSRM6CNSVMIFOICB54WNPCJMSMO55PEBMP'
API_HEADERS = {
    "accept": "application/json",
}

SOFTWARE_LIST = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]

def requestInfoAboutProgramInVulners(program, version):
    dataWrapper = {
        "software": program,
        "version": version,
        "type": "software",
        "maxVulnerabilities": 100,
        "apiKey": API_KEY
    }
    response = requests.post(API_URL, json=dataWrapper, headers=API_HEADERS)
    return response.json()

def printInfoAboutSoftware(program, version, jsonResponse):
    print(f'ПО: {program} : {version}')
    if 'result' in jsonResponse and jsonResponse['result'] != 'OK':
        print('Ничего не найдено')
        print('-----')
        print()
        return

    cveList = []
    exploitsMap = {}
    for value in jsonResponse['data']['search']:
        cveList.extend(value['_source']['cvelist'])
        # Проверяем есть ли эксплойты
        if value['_source']['bulletinFamily'] == 'exploit':
            for cve in value["_source"]["cvelist"]:
                exploitsMap[cve] = {
                    "href": value["_source"]["href"],
                    "description": value["_source"]["description"]
                }

    print('Список CVE:')
    print(cveList)
    print('Список эксплойтов: ')
    for cve, exploit in exploitsMap.items():
        print(f'{cve} -> Ссылка: {exploit["href"]} ; Описание: {exploit["description"]}')

    print('-----')
    print()

for item in SOFTWARE_LIST:
    jsonResponse = requestInfoAboutProgramInVulners(item["Program"], item["Version"])
    printInfoAboutSoftware(item["Program"], item["Version"], jsonResponse)
