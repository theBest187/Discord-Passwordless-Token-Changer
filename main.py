#* CREDITS TO https://github.com/Switch3301/Token-changer FOR THE ORIGINAL CODE
#* HUMANIZED & UNDETECTABLE VERSION

import random
import time
import toml
import ctypes
import threading
import tls_client
import hashlib
import websocket
import base64
import json
import os
import subprocess
import re
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from concurrent.futures import ThreadPoolExecutor, as_completed
from logmagix import Logger, Home
from functools import wraps

# --- KONFIGURATION & LOGGING ---
with open('input/config.toml') as f:
    config = toml.load(f)

DEBUG = config['dev'].get('Debug', False)
log = Logger()

output_folder = f"output/{time.strftime('%Y-%m-%d %H-%M-%S')}"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# --- GLOBALER BUILD-CACHE ---
CURRENT_DISCORD_BUILD = None

def get_current_build_number():
    """Scrapt die aktuelle Discord Build Number von den Assets."""
    global CURRENT_DISCORD_BUILD
    if CURRENT_DISCORD_BUILD: return CURRENT_DISCORD_BUILD
    
    try:
        response = requests.get("https://discord.com/app", timeout=10)
        script_files = re.findall(r'src="/assets/([a-z0-9]+)\.js"', response.text)
        for file in reversed(script_files):
            js_content = requests.get(f"https://discord.com/assets/{file}.js", timeout=10).text
            if "build_number" in js_content:
                build_num = re.search(r'build_number\s*:\s*["\'](\d+)["\']', js_content)
                if build_num:
                    CURRENT_DISCORD_BUILD = int(build_num.group(1))
                    log.info(f"Discord Build detected: {CURRENT_DISCORD_BUILD}")
                    return CURRENT_DISCORD_BUILD
    except: pass
    return 380213 # Fallback

# --- DECORATORS ---
def debug(func_or_message, *args, **kwargs):
    if callable(func_or_message):
        @wraps(func_or_message)
        def wrapper(*args, **kwargs):
            result = func_or_message(*args, **kwargs)
            if DEBUG: log.debug(f"{func_or_message.__name__} -> {result}")
            return result
        return wrapper
    elif DEBUG: log.debug(f"Debug: {func_or_message}")

# --- HILFSKLASSEN ---
class Miscellaneous:
    def get_proxies(self) -> dict:
        try:
            if config['dev'].get('Proxyless', False): return None
            with open('input/proxies.txt') as f:
                proxies = [line.strip() for line in f if line.strip()]
            if not proxies: return None
            proxy = random.choice(proxies)
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        except: return None

    def randomize_user_agent(self) -> tuple:
        # Fokus auf Chrome/Edge für stabilere Fingerprints
        os_list = [
            ("Windows NT 10.0; Win64; x64", "Windows", "chrome_131"),
            ("Macintosh; Intel Mac OS X 10_15_7", "Mac OS X", "chrome_131")
        ]
        platform_string, os_name, tls_id = random.choice(os_list)
        ver = f"{random.randint(128, 131)}.0.{random.randint(1000, 5000)}.{random.randint(10, 99)}"
        ua = f"Mozilla/5.0 ({platform_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"
        return ua, "Chrome", ver, os_name, tls_id

    def encode_public_key(self, pub_key) -> str:
        return base64.b64encode(pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def generate_nonce_proof(self, encrypted_nonce_b64, priv_key) -> str:
        dec_nonce = priv_key.decrypt(base64.b64decode(encrypted_nonce_b64), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.urlsafe_b64encode(hashlib.sha256(dec_nonce).digest()).rstrip(b"=").decode()

    def parse_token_line(self, line: str):
        parts = line.strip().split(":")
        for part in parts:
            if len(part) >= 70: return line.strip(), part
        raise ValueError("No token found")

# --- HAUPTKLASSE ---
class TokenChanger:
    def __init__(self, misc: Miscellaneous, proxy_dict: dict = None) -> None:
        self.misc = misc
        self.ua, self.browser, self.ver, self.os, self.tls_id = self.misc.randomize_user_agent()
        
        # TLS-Identifier muss zum User-Agent passen (Humanisierung)
        self.session = tls_client.Session(client_identifier=self.tls_id, random_tls_extension_order=True)
        self.session.proxies = proxy_dict
        self.session.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua-platform': f'"{self.os}"',
            'user-agent': self.ua,
            'x-discord-locale': 'en-US',
            'x-super-properties': self.gen_super_props()
        }

    def gen_super_props(self):
        props = {
            "os": self.os, "browser": self.browser, "device": "", "system_locale": "en-US",
            "browser_user_agent": self.ua, "browser_version": self.ver, "os_version": "",
            "referrer": "", "referring_domain": "", "release_channel": "stable",
            "client_build_number": get_current_build_number(), "client_event_source": None
        }
        return base64.b64encode(json.dumps(props).encode()).decode()

    def clone_token(self, token: str):
        try:
            # Human Delay: Simuliere das Öffnen der Seite
            time.sleep(random.uniform(1.5, 3.5))
            
            ws = websocket.create_connection("wss://remote-auth-gateway.discord.gg/?v=2", 
                                             header=[f"Authorization: {token}", "Origin: https://discord.com"],
                                             proxy_type="http", http_proxy_host=self.session.proxies['http'].split("//")[1].split(":")[0] if self.session.proxies else None)
            
            # Init RSA
            priv = rsa.generate_private_key(65537, 2048, default_backend())
            pub_enc = self.misc.encode_public_key(priv.public_key())
            
            ws.recv() # Hello
            ws.send(json.dumps({"op": "init", "encoded_public_key": pub_enc}))
            
            # Nonce & Proof
            nonce_data = json.loads(ws.recv())
            proof = self.misc.generate_nonce_proof(nonce_data["encrypted_nonce"], priv)
            ws.send(json.dumps({"op": "nonce_proof", "proof": proof}))
            
            # Fingerprint & Handshake
            fp_data = json.loads(ws.recv())
            self.session.headers['authorization'] = token
            
            # API Handshake
            h_res = self.session.post("https://discord.com/api/v9/users/@me/remote-auth", json={'fingerprint': fp_data['fingerprint']})
            if h_res.status_code != 200: return None
            
            self.session.post("https://discord.com/api/v9/users/@me/remote-auth/finish", json={'handshake_token': h_res.json()['handshake_token']})
            
            # Wait for Ticket
            ws.recv() # User payload
            ticket_data = json.loads(ws.recv())
            ws.close()
            
            # Login for new token
            time.sleep(random.uniform(1.0, 2.5))
            l_res = self.session.post("https://discord.com/api/v9/users/@me/remote-auth/login", json={"ticket": ticket_data['ticket']})
            
            if l_res.status_code == 200:
                enc_token = l_res.json().get("encrypted_token")
                dec_token = priv.decrypt(base64.b64decode(enc_token), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                return dec_token.decode('utf-8')
        except Exception as e:
            debug(f"Error: {e}")
        return None

    def logout(self, token):
        self.session.headers['authorization'] = token
        return self.session.post('https://discord.com/api/v9/auth/logout', json={'provider': None, 'voip_provider': None}).status_code == 204

# --- WORKER ---
def process_line(line, misc, lock):
    # Initialer Jitter gegen Detection
    time.sleep(random.uniform(1.0, 5.0))
    
    try:
        raw_line, token = misc.parse_token_line(line)
        changer = TokenChanger(misc, misc.get_proxies())
        
        new_token = changer.clone_token(token)
        if new_token:
            time.sleep(random.uniform(2.0, 4.0)) # Menschliche Pause vor Logout
            if changer.logout(token):
                log.message("Success", f"Updated: {new_token[:35]}...", time.time(), time.time())
                with lock:
                    with open(f"{output_folder}/tokens.txt", "a") as f: f.write(raw_line.replace(token, new_token) + "\n")
                return True
        else:
            with lock:
                with open(f"{output_folder}/failed.txt", "a") as f: f.write(line + "\n")
    except: pass
    return False

def main():
    misc = Miscellaneous()
    Home("Humanized Changer", align="center").display()
    get_current_build_number() # Einmalig beim Start laden
    
    with open("input/tokens.txt", 'r') as f:
        lines = [l.strip() for l in f if l.strip()]

    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=config['dev'].get('Threads', 1)) as exe:
        futures = [exe.submit(process_line, line, misc, lock) for line in lines]
        for _ in as_completed(futures): pass

    log.info("Finished. Press Enter to exit.")
    input()

if __name__ == "__main__":
    main()
