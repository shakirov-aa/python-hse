import json
import os
import requests
import tempfile
from zipfile import ZipFile

API_URL = "https://www.virustotal.com/api/v3/files"  # URL, куда грузим файл для проверки
API_KEY = '088415795c6d6f393485e0b73802571de43afb293c1a4926e3e645abce66569f'  # API KEY
API_HEADERS = {
    "accept": "application/json",
    "X-Apikey": API_KEY
}

CATEGORIES_MALICIOUS = {'malicious', 'suspicious'}

print('Введите абсолютный путь к архиву')
filePath = input()
print('Введите пароль к архиву')
pwdInput = input()


def analyzeFileInVirusTotal(dir, file):
    filesWrapper = {"file": (file, open(os.path.join(dir, file), "rb"))}
    response = requests.post(API_URL, files=filesWrapper, headers=API_HEADERS)

    analysesUrl = response.json()["data"]["links"]["self"]
    analysesResponse = requests.get(analysesUrl, headers=API_HEADERS)
    print('Результаты анализа файла ' + file)
    print('Краткие результаты:')
    analysesFullJson = analysesResponse.json()
    print(json.dumps(analysesFullJson["data"]["attributes"]["stats"], indent=4))

    antiviruses = analysesFullJson["data"]["attributes"]["results"]
    print()
    print('Антивирусы, которые обнаружили угрозы:')

    for antivirus, result in antiviruses.items():
        if result["category"] in CATEGORIES_MALICIOUS:
            print(f"{antivirus}: {result}")

    print()
    print('Антивирусы, которые НЕ обнаружили угрозы:')
    for antivirus, result in antiviruses.items():
        if result["category"] not in CATEGORIES_MALICIOUS:
            print(f"{antivirus}: {result}")


# Создаем временную директорию, куда распакуем архив
with tempfile.TemporaryDirectory() as tmpDir:
    with ZipFile(filePath) as zf:
        zf.extractall(path=tmpDir, pwd=bytes(pwdInput, 'utf-8'))

        # Итерируемся по файлам, которые распаковали из архива
        for fileFromArchive in os.listdir(tmpDir):
            analyzeFileInVirusTotal(tmpDir, fileFromArchive)
