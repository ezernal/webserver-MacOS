from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory # type: ignore
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user # type: ignore
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
import jwt # type: ignore
import datetime
import logging
import zlib

app = Flask(__name__)

# Настройки для сессий
app.secret_key = 'your_secret_key'  # Секретный ключ для сессий

# Папка для сохранения загруженных файлов
UPLOAD_FOLDER = './uploaded_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Настройка логирования
LOG_FILE = 'app.log'
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,  # Уровень логирования
    format='%(asctime)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

logging.info("Сервер запущен.")

# Инициализация LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Файл с пользователями
USERS_FILE = 'users.json'

# Загрузка пользователей из JSON-файла
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Сохранение пользователей в JSON-файл
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Создание класса User
class User(UserMixin):
    def __init__(self, username):
        self.id = username

    @staticmethod
    def get(user_id):
        users = load_users()
        if user_id in users:
            return User(user_id)
        return None

# Загрузка пользователя по ID
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Генерация JWT токена
def generate_token(username):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    token = jwt.encode({'username': username, 'exp': expiration}, app.secret_key, algorithm='HS256')
    logging.info(f"Токен сгенерирован для пользователя {username}.")
    return token

# Декодирование JWT токена
def decode_token(token):
    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        logging.warning("Просроченный токен.")
        return None
    except jwt.InvalidTokenError:
        logging.error("Некорректный токен.")
        return None

# Функция для сжатия файла
def compress_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        compressed_data = zlib.compress(original_data, level=zlib.Z_BEST_COMPRESSION)
        
        with open(file_path, 'wb') as f:
            f.write(compressed_data)

        compressed_size = os.path.getsize(file_path)
        logging.info(f"Файл {file_path} успешно сжат до {compressed_size} байт.")
        return True
    except Exception as e:
        logging.error(f"Ошибка сжатия файла {file_path}: {str(e)}")
        return False

# Функция для распаковки файла
def decompress_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            compressed_data = f.read()
        
        original_data = zlib.decompress(compressed_data)
        
        temp_file_path = f"{file_path}.decompressed"
        with open(temp_file_path, 'wb') as f:
            f.write(original_data)
        
        logging.info(f"Файл {file_path} успешно распакован.")
        return temp_file_path
    except Exception as e:
        logging.error(f"Ошибка распаковки файла {file_path}: {str(e)}")
        return None

@app.route('/')
def home():
    logging.info("Запрос главной страницы.")
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            token = generate_token(username)
            session['token'] = token
            logging.info(f"Пользователь {username} успешно вошел в систему.")
            return redirect(url_for('home'))
        else:
            logging.warning(f"Неудачная попытка входа для пользователя {username}.")
            flash('Неверный логин или пароль', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logging.info(f"Пользователь {current_user.id} вышел из системы.")
    logout_user()
    session.pop('token', None)
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        
        if password != password_confirm:
            logging.warning(f"Регистрация не удалась: пароли не совпадают для пользователя {username}.")
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')
        
        users = load_users()
        
        if username in users:
            logging.warning(f"Попытка регистрации с существующим именем пользователя {username}.")
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('register.html')
        
        users[username] = generate_password_hash(password)
        save_users(users)
        logging.info(f"Новый пользователь зарегистрирован: {username}.")
        flash('Регистрация успешна!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            logging.error("Попытка загрузить файл без данных.")
            return "Файл не найден в запросе", 400
        file = request.files['file']
        if file.filename == '':
            logging.error("Попытка загрузить файл с пустым именем.")
            return "Файл не выбран", 400
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        logging.info(f"Пользователь {current_user.id} загрузил файл {file.filename}.")
        
        # Автоматическое сжатие файла
        if compress_file(file_path):
            logging.info(f"Файл {file.filename} автоматически сжат после загрузки.")
        else:
            logging.error(f"Ошибка сжатия файла {file.filename} после загрузки.")
            return "Ошибка сжатия файла", 500
        
        return redirect(url_for('uploaded_files'))
    return render_template('upload.html')

@app.route('/files')
@login_required
def uploaded_files():
    logging.info("Запрос списка загруженных файлов.")
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('files.html', files=files)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        logging.error(f"Попытка скачать несуществующий файл {filename}.")
        return "Файл не найден", 404

    # Распаковка файла перед скачиванием
    decompressed_file = decompress_file(file_path)
    if decompressed_file:
        response = send_from_directory(
            directory=os.path.dirname(decompressed_file),
            path=os.path.basename(decompressed_file),
            as_attachment=True
        )
        os.remove(decompressed_file)  # Удалить временный распакованный файл
        logging.info(f"Файл {filename} распакован и отправлен пользователю {current_user.id}.")
        return response
    else:
        logging.error(f"Ошибка распаковки файла {filename} перед скачиванием.")
        return "Ошибка распаковки файла", 500

@app.route('/software')
@login_required
def software():
    logging.info("Запрос страницы с программным обеспечением.")
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('software.html', files=files)

@app.route('/install/<filename>')
@login_required
def install(filename):
    logging.info(f"Установка программы {filename} инициирована пользователем {current_user.id}.")
    return f"""
        <h1>Установка {filename}</h1>
        <p>Для установки программы на Mac, выполните следующий скрипт:</p>
        <pre>#!/bin/bash
curl -o /tmp/{filename} http://127.0.0.1:5000/download/{filename}
sudo installer -pkg /tmp/{filename} -target /</pre>
        <p><a href='/software'>Назад к ПО для установки</a></p>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
