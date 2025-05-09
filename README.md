# 🛡️ Автономна система аналізу та усунення вразливостей (Nessus + AI)  

Цей проєкт виконує аналіз уразливостей за допомогою **Nessus**, обробляє результати та надає рекомендації щодо виправлення через **ШІ (GPT-4, g4f)**.  

## 🚀 Функціонал  
✅ Отримує дані про останні сканування Nessus.  
✅ Аналізує знайдені уразливості.  
✅ Використовує ШІ для генерації рекомендацій.  
✅ Виводить готові Bash-команди для виправлення уразливостей.  
✅ Має веб-інтерфейс на Flask для перегляду результатів.  


## 🧰 Схема розміщення в папці 
```
📂 folder/                  # Головна папка проєкту
│── 📄 scanner.py           # Основний файл
│── 📂 templates/                 
│    │── 📄 index.html       # HTML-файли для веб-інтерфейсу
```

---

## 📦 Встановлення та налаштування  

### 1️⃣ **Встановлення Python**
Переконайтесь, що у вас встановлений Python **3.8+**  
Перевірте командою:  
```
python --version
```
Якщо Python не встановлений, скачайте його з офіційного сайту.

Якщо потрібно встановити Python через термінал (Linux/macOS):
```
sudo apt update && sudo apt install python3 python3-pip -y  # Для Ubuntu/Debian
```
```
sudo yum install python3 python3-pip -y  # Для CentOS/RHEL
```
```
brew install python3  # Для macOS (через Homebrew)
```

2️⃣Встановлення бібліотек 
```
pip install Flask requests urllib3 g4f
```
3️⃣ Налаштування Nessus API
Щоб взаємодіяти з Nessus, потрібно вказати URL, логін і пароль.
Відредагуйте config.py:

NESSUS_URL = "https://your-nessus-server:8834"

USERNAME = "your-username"

PASSWORD = "your-password"

🏃‍♂️ Запуск сервера

Щоб запустити веб-інтерфейс, виконайте:
```
python scanner.py
```
Після цього відкрийте браузер і перейдіть за адресою:
```
http://127.0.0.1:5000/
```
