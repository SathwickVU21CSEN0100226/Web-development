import sqlite3
import os

DATABASE_FILE = 'app.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if not os.path.exists(DATABASE_FILE):
        conn = get_db_connection()
        with open('schema.sql', 'r') as f:
            conn.executescript(f.read())
        conn.close()
        print("Database initialized.")
    else:
        print("Database already exists.")
        conn = get_db_connection()
        try:
            conn.execute("ALTER TABLE files ADD COLUMN secret_key TEXT;")
            conn.close()
            print("Added secret_key column")
        except:
            conn.close()
            print("secret_key column already present")


def execute_query(query, args=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    conn.close()


def fetch_data(query, args=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    rows = cur.fetchall()
    conn.close()
    return rows


def fetch_one(query, args=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    row = cur.fetchone()
    conn.close()
    return row


def clean_database():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM files")
    cur.execute("DELETE FROM user_files")
    conn.commit()
    conn.close()
    print("Database cleaned")

def get_users_for_file(file_id):
  conn = get_db_connection()
  cur = conn.cursor()
  cur.execute("""SELECT users.username FROM users
              INNER JOIN user_files ON users.id = user_files.user_id
              WHERE user_files.file_id = ?""", (file_id,))
  rows = cur.fetchall()
  conn.close()
  return rows

if __name__ == '__main__':
    init_db()
    #clean_database()