import re
import g4f
from flask import Flask, jsonify, render_template
import requests
from urllib3.exceptions import InsecureRequestWarning

# Отключаем предупреждения SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Настройки Flask
app = Flask(__name__)

# Настройки подключения к Nessus
NESSUS_URL = "https://ip:8834"#замінити
USERNAME = "логін" #замінити
PASSWORD = "пароль"#замінити

def get_token():
    """Получаем токен авторизации от Nessus"""
    auth_url = f"{NESSUS_URL}/session"
    auth_data = {"username": USERNAME, "password": PASSWORD}
    response = requests.post(auth_url, json=auth_data, verify=False)

    if response.status_code == 200:
        return response.json().get("token")
    return None

def get_latest_scan_id(token):
    """Получаем ID последнего сканирования"""
    scans_url = f"{NESSUS_URL}/scans"
    headers = {"X-Cookie": f"token={token}", "Content-Type": "application/json"}
    response = requests.get(scans_url, headers=headers, verify=False)

    if response.status_code == 200:
        scans = response.json().get("scans", [])
        if scans:
            latest_scan = sorted(scans, key=lambda x: x["last_modification_date"], reverse=True)[0]
            return latest_scan["id"]
    return None

def get_vulnerabilities(token, scan_id):
    """Получаем список уязвимостей для сканирования"""
    vulns_url = f"{NESSUS_URL}/scans/{scan_id}"
    headers = {"X-Cookie": f"token={token}", "Content-Type": "application/json"}
    response = requests.get(vulns_url, headers=headers, verify=False)

    if response.status_code == 200:
        return response.json().get("vulnerabilities", [])
    return []

def get_recommendation_for_vulnerability(vulnerability_description):
    """Генерирует рекомендацию для устранения уязвимости с помощью g4f."""
    try:
        response = g4f.ChatCompletion.create(
            model="gpt-4",
            provider=g4f.Provider.Goabror,
            messages=[{"role": "user", "content": f"Як виправити вразливість: {vulnerability_description}?"}], 
            language="uk"
        )

        print("Ответ от AI:", response)

        if isinstance(response, str):
            return response  
        elif isinstance(response, dict) and "choices" in response:
            return response["choices"][0]["message"]["content"]
        else:
            return f"Помилка: Непідтримуваний формат відповіді ШI: {response}"

    except Exception as e:
        return f"Помилка при запиті ШI: {str(e)}"

def extract_bash_commands(description):
    """Извлекает команды Bash из текста"""
    bash_command_pattern = r"```bash\n(.*?)\n```"
    
    # Найти все блоки `bash ...`
    matches = re.findall(bash_command_pattern, description, re.DOTALL)

    # Разделить по операционным системам
    bash_commands = {
        "debian/ubuntu": [],
        "centos/rhel": [],
        "fedora": [],
        "arch": [],
        "macos": [],
        "windows": [],
        "generic": []
    }

    for block in matches:
        commands = block.strip().split("\n")

        # Определение системы по содержимому команд
        if any("apt" in cmd for cmd in commands):
            bash_commands["debian/ubuntu"].extend(commands)
        elif any("yum" in cmd for cmd in commands):
            bash_commands["centos/rhel"].extend(commands)
        elif any("dnf" in cmd for cmd in commands):
            bash_commands["fedora"].extend(commands)
        elif any("pacman" in cmd for cmd in commands):
            bash_commands["arch"].extend(commands)
        elif any("brew" in cmd for cmd in commands):
            bash_commands["macos"].extend(commands)
        elif any("powershell" in cmd.lower() or "winget" in cmd.lower() for cmd in commands):
            bash_commands["windows"].extend(commands)
        else:
            bash_commands["generic"].extend(commands)

    return bash_commands

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/vulnerabilities', methods=['GET'])
def vulnerabilities():
    token = get_token()
    if not token:
        return jsonify({"error": "Не вдалося отримати токен"}), 401

    scan_id = get_latest_scan_id(token)
    if not scan_id:
        return jsonify({"error": "Немає доступних сканувань"}), 404

    vulns = get_vulnerabilities(token, scan_id)

    for vuln in vulns:
        description = vuln.get("plugin_name", "Опис вразливості відсутній.")
        recommendation = get_recommendation_for_vulnerability(description)

        if recommendation:
            vuln["recommendation"] = recommendation
        
        bash_commands = extract_bash_commands(recommendation)
        if any(bash_commands.values()):  
            vuln["bash_commands"] = bash_commands

    return jsonify({"vulnerabilities": vulns})

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5000, debug=True)

