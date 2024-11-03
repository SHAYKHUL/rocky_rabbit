from flask import Flask, request, jsonify, render_template
import sqlite3
import json
from contextlib import closing

app = Flask(__name__)

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

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/store_data', methods=['POST'])
def store_data():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        salt = data.get('salt')
        system_info = data.get('system_info')

        if not all([username, password, salt, system_info]):
            return jsonify({"error": "Missing required fields"}), 400

        with closing(sqlite3.connect('user_data.db')) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, salt, system_info) VALUES (?, ?, ?, ?)', 
                      (username, password, salt, json.dumps(system_info)))
            conn.commit()

        return jsonify({"message": "Data stored successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error storing data: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/show_data', methods=['GET'])
def show_data():
    page = int(request.args.get('page', 1))
    per_page = 12  # Number of records per page
    offset = (page - 1) * per_page

    with closing(sqlite3.connect('user_data.db')) as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT username, password, salt, system_info FROM users LIMIT ? OFFSET ?', (per_page, offset))
        rows = c.fetchall()

        users = []
        for row in rows:
            system_info = json.loads(row[3])  # Parse the system_info JSON
            users.append({
                "username": row[0],
                "password": row[1],
                "salt": row[2],
                "system_info": system_info
            })

    total_pages = (total_users + per_page - 1) // per_page
    return render_template('show_data.html', users=users, page=page, total_pages=total_pages)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    with closing(sqlite3.connect('user_data.db')) as conn:
        c = conn.cursor()
        c.execute('SELECT username, password, salt, system_info FROM users WHERE username LIKE ?', ('%' + query + '%',))
        rows = c.fetchall()
        
    users = []
    for row in rows:
        system_info = json.loads(row[3])
        users.append({
            "username": row[0],
            "password": row[1],
            "salt": row[2],
            "system_info": system_info
        })
    
    return jsonify(users)

if __name__ == '__main__':
    init_db()  # Initialize the database and create the table
    app.run(debug=True)
