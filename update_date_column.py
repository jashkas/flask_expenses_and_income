import sqlite3
from datetime import datetime

# Путь к файлу базы данных
db_path = 'instance\database.db'

# Подключаемся к базе данных
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Добавляем новый столбец "date" в формате DATE
try:
    cursor.execute('ALTER TABLE expense ADD COLUMN date DATE;')
    print("Добавлен новый столбец 'date'.")
except sqlite3.OperationalError:
    print("Столбец 'date' уже существует.")

# Получаем текущую дату в нужном формате
current_date = "11.03.2025"
date_obj = datetime.strptime(current_date, '%d.%m.%Y').date()

# Обновляем все существующие строки, устанавливая текущую дату
cursor.execute('UPDATE expense SET date = ?;', (date_obj, ))
print(f"Все строки в таблице 'expense' обновлены с текущей датой: {current_date}")

# Сохраняем изменения и закрываем соединение
conn.commit()
conn.close()

print("Изменения успешно внесены.")