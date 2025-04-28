from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import hashlib
import os
from datetime import datetime
from database import init_db, get_db_connection, execute_query, fetch_data, fetch_one
import time
import threading
import mimetypes
import base64
import secrets
import hmac

app = Flask(__name__)
app.secret_key = "secretkey"
init_db()
app.config['FILE_HASHES'] = {}  # Store generated hashes
app.config['FILE_CODES'] = {}  # Store generated codes
app.config['BASELINE_HASHES'] = {} # Store the initial hash values

# Check if an admin user exists, if not create one
def check_and_create_admin():
    admin = fetch_one("SELECT * FROM users WHERE role = 'admin'")
    if not admin:
        execute_query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      ('admin', 'admin123', 'admin'))
        print("Admin user created.")

check_and_create_admin()

def generate_baseline_hashes():
  files = fetch_data("SELECT * FROM files")
  baseline_hashes = {}
  for file in files:
    try:
      with open(file['file_path'], 'rb') as f:
        file_content = f.read()
      new_hash = hash_file(file_content)
      baseline_hashes[file['id']] = new_hash # store the hash values in the dictionary
    except Exception as e:
      print(f"Error generating base line hash for {file['file_name']} : {e}")
  app.config['BASELINE_HASHES'] = baseline_hashes

# Function to regenerate hashes
def regenerate_hashes():
    while True:
        files = fetch_data("SELECT * FROM files")
        new_hashes = {}
        new_codes={}
        for file in files:
          try:
            with open(file['file_path'], 'rb') as f:
              file_content = f.read()
            new_hash = hash_file(file_content)
            new_hashes[file['id']] = new_hash # store the hash values in the dictionary
            secret_key = file['secret_key']
            if secret_key:
                time_code = hmac.new(secret_key.encode('utf-8'), str(int(time.time()) // 60).encode('utf-8'), hashlib.sha256).hexdigest()
                new_codes[file['id']] = time_code[:10] # store the generated time codes in the dictionary
          except Exception as e:
            print(f"Error reading file: {e}")
            new_hashes[file['id']] = "Error reading file"
        app.config['FILE_HASHES'] = new_hashes
        app.config['FILE_CODES'] = new_codes
        print("Hashes and Time Based Codes regenerated.")
        time.sleep(60)  # 60 seconds


# Function to hash the file content
def hash_file(file_content):
    hasher = hashlib.sha256()
    hasher.update(file_content)
    return hasher.hexdigest()

# Start the background thread for hash regeneration
hash_thread = threading.Thread(target=regenerate_hashes, daemon=True)
hash_thread.start()

#Generate baseline hash values
generate_baseline_hashes()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = fetch_one("SELECT * FROM users WHERE username = ?", (username,))

        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash("Logged In Successfully", "success")
            execute_query("INSERT INTO logs (log_type, user_id) VALUES (?, ?)",
                        ('login', session['user_id']))
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'analyst':
                return redirect(url_for('analyst_dashboard'))
            elif user['role'] == 'designer':
                return redirect(url_for('designer_dashboard'))
            else:
                return redirect(url_for('guest_dashboard'))
        else:
           flash("Invalid Login Credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        execute_query("INSERT INTO logs (log_type, user_id) VALUES (?, ?)",
                        ('logout', session['user_id']))
        session.pop('user_id', None)
        session.pop('role', None)
        flash("Logged Out Successfully", "success")
    return redirect(url_for('login'))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    files = fetch_data("SELECT * FROM files")
    logs = fetch_data(
        "SELECT logs.*, users.username, logs.log_time FROM logs LEFT JOIN users ON logs.user_id = users.id ORDER BY log_time DESC LIMIT 10")
    return render_template('admin_dashboard.html', files=files, logs=logs)


@app.route('/admin/create_user', methods=['GET', 'POST'])
def create_user():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        execute_query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (username, password, role))
        flash('User created successfully', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_user.html')


@app.route('/admin/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)
            with open(file_path, 'rb') as f:
               file_content = f.read()
            hash_value = hash_file(file_content)
            secret_key = secrets.token_urlsafe(32)
            execute_query("INSERT INTO files (file_name, file_path, hash_value, secret_key) VALUES (?, ?, ?, ?)",
                           (file.filename, file_path, hash_value, secret_key))
            flash('File uploaded successfully', 'success')
            generate_baseline_hashes()
        return redirect(url_for('admin_dashboard'))
    return render_template('upload.html')


@app.route('/admin/assign_files', methods=['GET', 'POST'])
def assign_files():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    users = fetch_data("SELECT * FROM users")
    files = fetch_data("SELECT * FROM files")
    if request.method == 'POST':
        user_id = request.form['user_id']
        file_id = request.form['file_id']
        execute_query("INSERT INTO user_files (user_id, file_id) VALUES (?, ?)",
                        (user_id, file_id))
        flash('File assigned successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('assign_files.html', users=users, files=files)


@app.route('/admin/logs')
def admin_logs():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    logs = fetch_data("SELECT logs.*, users.username FROM logs LEFT JOIN users ON logs.user_id = users.id ORDER BY log_time DESC")
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/files_json')
def admin_files_json():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    files = fetch_data("SELECT * FROM files")
    # Convert sqlite3.Row objects to dictionaries
    files_list = []
    for file in files:
        file_dict = dict(file)
        file_dict['hash_value'] = app.config['FILE_HASHES'].get(file['id'],"")
        file_dict['baseline_hash'] = app.config['BASELINE_HASHES'].get(file['id'],"")
        file_dict['time_code'] = app.config['FILE_CODES'].get(file['id'],"")
        files_list.append(file_dict)
    return jsonify(files_list)

@app.route('/admin/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    file = fetch_one("SELECT * FROM files WHERE id = ?", (file_id,))
    if file:
        try:
            os.remove(file['file_path'])
        except Exception as e:
            flash(f'Error deleting file: {e}', 'danger')
            return redirect(url_for('admin_dashboard'))

        execute_query("DELETE FROM files WHERE id = ?", (file_id,))
        execute_query("DELETE FROM user_files WHERE file_id = ?", (file_id,))

        flash('File deleted successfully', 'success')
        generate_baseline_hashes()
    else:
         flash('File not found', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/generate_baseline', methods=['POST'])
def generate_baseline():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    generate_baseline_hashes()
    flash("New baseline hash generated", 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/analyst/dashboard')
def analyst_dashboard():
    if 'user_id' not in session or session['role'] != 'analyst':
        return redirect(url_for('login'))
    files = get_files_for_user(session['user_id'])
    logs = fetch_data(
        "SELECT logs.*, users.username FROM logs LEFT JOIN users ON logs.user_id = users.id WHERE users.role IN ('designer','guest') ORDER BY log_time DESC")
    return render_template('analyst_dashboard.html', files=files, logs=logs)


@app.route('/designer/dashboard')
def designer_dashboard():
    if 'user_id' not in session or session['role'] != 'designer':
        return redirect(url_for('login'))
    files = get_files_for_user(session['user_id'])
    logs = fetch_data(
        "SELECT logs.*, users.username FROM logs LEFT JOIN users ON logs.user_id = users.id WHERE users.role = 'guest' ORDER BY log_time DESC")
    return render_template('designer_dashboard.html', files=files, logs=logs)


@app.route('/guest/dashboard')
def guest_dashboard():
    if 'user_id' not in session or session['role'] != 'guest':
        return redirect(url_for('login'))
    files = get_files_for_user(session['user_id'])
    return render_template('guest_dashboard.html', files=files)


def get_files_for_user(user_id):
    files = fetch_data(
        """SELECT files.* FROM files INNER JOIN user_files ON files.id = user_files.file_id WHERE user_files.user_id = ?""",
        (user_id,))
    return files


@app.route('/file/<int:file_id>', methods=['GET', 'POST'])
def view_file(file_id):
    file = fetch_one("SELECT * FROM files WHERE id = ?", (file_id,))
    file_content = None
    file_type = None
    file_error = None

    if not file:
        flash('File not found', 'danger')
        return redirect(request.referrer)

    if request.method == 'POST':
        hash_input = request.form['hash_input']
        current_code = app.config['FILE_CODES'].get(file['id'], "")
        if hash_input == current_code:
            try:
                print(f"Attempting to open file: {file['file_path']}")
                file_type = mimetypes.guess_type(file['file_path'])[0]
                with open(file['file_path'], 'rb') as f:
                    if file_type and file_type.startswith('text/'):
                         file_content = f.read().decode('utf-8', 'ignore')
                    else:
                      execute_query(
                           "INSERT INTO logs (log_type, user_id, file_id) VALUES (?, ?, ?)",
                           ('file_access', session['user_id'], file_id))
                      return send_file(file['file_path'],mimetype=file_type, as_attachment=True, download_name=file['file_name'])


            except Exception as e:
                print(f"Error opening file: {e}")
                file_error = f'Error opening file: {e}'
                flash(file_error, 'danger')
        else:
            flash("Incorrect Access Code", "danger")

    return render_template('view_file.html', file=file, file_content=file_content, file_type=file_type,file_error=file_error)


if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True)