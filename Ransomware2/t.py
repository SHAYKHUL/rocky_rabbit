import sqlite3
import json
from faker import Faker
from contextlib import closing

# Initialize Faker
fake = Faker()

# Create a connection to the SQLite database
def init_db():
    with closing(sqlite3.connect('user_data.db')) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                system_info TEXT NOT NULL
            )
        ''')
        conn.commit()

# Populate the database with sample data
def populate_db(num_entries):
    with closing(sqlite3.connect('user_data.db')) as conn:
        c = conn.cursor()
        for _ in range(num_entries):
            username = fake.user_name()
            password = fake.password()
            salt = fake.md5()  # Fake salt for demonstration
            system_info = {
                "os": fake.random_element(elements=("Windows", "Linux", "macOS")),
                "version": f"{fake.random_int(1, 10)}.{fake.random_int(0, 9)}.{fake.random_int(0, 9)}",  # Simulated version
                "ip_address": fake.ipv4(),
                "additional_info": fake.text(max_nb_chars=100)  # Some extra info
            }
            c.execute('INSERT INTO users (username, password, salt, system_info) VALUES (?, ?, ?, ?)', 
                      (username, password, salt, json.dumps(system_info)))
        conn.commit()

if __name__ == '__main__':
    init_db()  # Initialize the database and create the table
    populate_db(100)  # Change this number for more or fewer entries
    print("Database populated with sample user data.")
