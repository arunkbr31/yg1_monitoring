import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'instance', 'database.db')

if not os.path.exists(db_path):
    print(f"Database not found at {db_path}. Run app.py first to create it.")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE audit ADD COLUMN ygct_plant2 VARCHAR(100) DEFAULT ''")
    print("Added column: ygct_plant2")
except sqlite3.OperationalError as e:
    if 'duplicate column name' in str(e).lower():
        print("Column ygct_plant2 already exists, skipping.")
    else:
        raise

try:
    cursor.execute("ALTER TABLE audit ADD COLUMN ygct_plant3 VARCHAR(100) DEFAULT ''")
    print("Added column: ygct_plant3")
except sqlite3.OperationalError as e:
    if 'duplicate column name' in str(e).lower():
        print("Column ygct_plant3 already exists, skipping.")
    else:
        raise

conn.commit()
conn.close()
print("Migration completed successfully.")
