from zipfile import ZipFile
import tempfile
import requests
import os
import json

API_URL = "https://www.virustotal.com/api/v3/files"  # URL, куда грузим файл для проверки
API_KEY = '088415795c6d6f393485e0b73802571de43afb293c1a4926e3e645abce66569f'  # API KEY
API_HEADERS = {
    "accept": "application/json",
    "X-Apikey": API_KEY
}

print('Enter absolute archive file path')
filePath = input()
print('Enter archive password')
pwdInput = input()


def analyzeFileInVirusTotal(dir, file):
    filesWrapper = {"file": (file, open(os.path.join(dir, file), "rb"))}
    response = requests.post(API_URL, files=filesWrapper, headers=API_HEADERS)

    analysesUrl = response.json()["data"]["links"]["self"]
    analysesResponse = requests.get(analysesUrl, headers=API_HEADERS)
    print(json.dumps(analysesResponse.json(), indent=4))


# Создаем временную директорию, куда распакуем архив
with tempfile.TemporaryDirectory() as tmpDir:
    with ZipFile(filePath) as zf:
        zf.extractall(path=tmpDir, pwd=bytes(pwdInput, 'utf-8'))
        print('Archive extracted to temporary dir')

        # Итерируемся по файлам, которые распаковали из архива
        for fileFromArchive in os.listdir(tmpDir):
            analyzeFileInVirusTotal(tmpDir, fileFromArchive)

