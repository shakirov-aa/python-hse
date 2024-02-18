import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Загружаем события из файла
with open('resources/events.json') as json_file:
    data = json.load(json_file)

# Преобразование в DataFrame
df = pd.DataFrame(data["events"])

# Визуализация
plt.figure(figsize=(12, 4))
sns.countplot(data=df, x="signature")

plt.title("Распределение типов событий безопасности")
plt.xticks(rotation=90)
plt.show()
