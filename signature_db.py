import os
import json
import time
import subprocess
import threading

try:
    import requests
except ImportError:
    requests = None

try:
    import yara
except ImportError:
    yara = None

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
HASHES_FILE = os.path.join(DATA_DIR, "hashes.json")
YARA_DIR = os.path.join(DATA_DIR, "yara_rules")
SIGBASE_DIR = os.path.join(YARA_DIR, "signature-base")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
CACHE_TTL_HOURS = 6
MAX_HASHES = 20000

def _load_config_key():
    env = os.getenv("MALWAREBAZAAR_AUTH_KEY", "")
    if env:
        return env
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("malwarebazaar_auth_key", "")
    except Exception:
        return ""

class SignatureDB:
    def __init__(self, log_cb=None):
        self.log = log_cb or (lambda msg: None)
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(YARA_DIR, exist_ok=True)

        self.hashes = {}
        self.yara_rules = None
        self._lock = threading.Lock()
        self._loaded_at = 0
        self.auth_key = _load_config_key()

        self._load_hashes()
        
        # Запускаем обновление и YARA в фоне
        threading.Thread(target=self._bg_init, daemon=True).start()

    def _bg_init(self):
        self._maybe_refresh_hashes()
        self._load_yara()

    # ---------------- ХЭШИ ----------------
    def _load_hashes(self):
        if os.path.exists(HASHES_FILE):
            try:
                with open(HASHES_FILE, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                self.hashes = payload.get("hashes", {})
                self._loaded_at = payload.get("loaded_at", 0)
                self.log(f"[DB] Загружено {len(self.hashes)} хэшей из кэша")
            except Exception as e:
                self.log(f"[DB] Ошибка чтения кэша: {e}")
                self.hashes = {}
                self._loaded_at = 0

    def _save_hashes(self):
        payload = {
            "loaded_at": self._loaded_at,
            "count": len(self.hashes),
            "hashes": self.hashes,
        }
        tmp = HASHES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, HASHES_FILE)

    def _maybe_refresh_hashes(self, force=False):
        if requests is None or not self.auth_key:
            return
        age = time.time() - self._loaded_at
        if not force and age < CACHE_TTL_HOURS * 3600 and self.hashes:
            return

        self.log("[DB] Обновление хэшей из MalwareBazaar...")
        try:
            added = self._fetch_malwarebazaar()
            self._loaded_at = time.time()
            self._save_hashes()
            self.log(f"[DB] Добавлено {added}, всего {len(self.hashes)}")
        except Exception as e:
            self.log(f"[DB] Ошибка обновления: {e}")

    def _fetch_malwarebazaar(self):
        added = 0
        headers = {"Auth-Key": self.auth_key}
        # Исправлено: selector=100 (API MalwareBazaar больше не принимает 1000)
        try:
            r = requests.post(
                MALWAREBAZAAR_API,
                data={"query": "get_recent", "selector": "100"},
                headers=headers,
                timeout=30,
            )
            r.raise_for_status()
            data = r.json()
            if data.get("query_status") != "ok":
                self.log(f"[DB] MalwareBazaar: {data.get('query_status')}")
                return 0
            for entry in data.get("data", []):
                h = entry.get("sha256_hash", "").lower()
                if h and h not in self.hashes:
                    tag = entry.get("signature") or entry.get("file_type") or "malware"
                    self.hashes[h] = tag
                    added += 1
                    if len(self.hashes) >= MAX_HASHES:
                        break
        except Exception as e:
            self.log(f"[DB] MalwareBazaar запрос упал: {e}")
        return added

    # ---------------- YARA ----------------
    def _load_yara(self):
        if yara is None:
            return

        if not os.path.isdir(SIGBASE_DIR):
            self.log("[DB] Клонирование signature-base (это займет время)...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1",
                     "https://github.com/Neo23x0/signature-base.git",
                     SIGBASE_DIR],
                    check=True, capture_output=True, timeout=180,
                )
                self.log("[DB] signature-base склонирован")
            except Exception as e:
                self.log(f"[DB] Ошибка клонирования: {e}")
                return

        rule_files = {}
        for root, _, files in os.walk(os.path.join(SIGBASE_DIR, "yara")):
            for fn in files:
                if fn.endswith((".yar", ".yara")):
                    path = os.path.join(root, fn)
                    ns = os.path.relpath(path, SIGBASE_DIR).replace(os.sep, "_")
                    rule_files[ns] = path

        if not rule_files:
            return

        self.log(f"[DB] Компиляция YARA... (может занять пару минут)")
        
        # Компилируем пакетами по 50 файлов, чтобы не вылетала ошибка путей
        valid_rules = {}
        for ns, path in rule_files.items():
            try:
                yara.compile(filepath=path)
                valid_rules[ns] = path
            except Exception:
                pass # Игнорируем сломанные правила
                
        if valid_rules:
            try:
                self.yara_rules = yara.compile(filepaths=valid_rules)
                self.log(f"[DB] Успешно скомпилировано {len(valid_rules)} YARA-файлов")
            except Exception as e:
                self.log(f"[DB] Финальная компиляция упала: {e}")

    def match_yara(self, filepath):
        if not self.yara_rules:
            return []
        try:
            matches = self.yara_rules.match(filepath, timeout=15)
            return [(m.rule, list(m.tags)) for m in matches]
        except Exception:
            return []

    # ---------------- API ----------------
    def lookup_hash(self, sha256):
        with self._lock:
            return self.hashes.get(sha256.lower())

    def stats(self):
        return {
            "hashes": len(self.hashes),
            "yara_loaded": self.yara_rules is not None,
            "cache_age_hours": (time.time() - self._loaded_at) / 3600
                               if self._loaded_at else None,
            "auth_key_set": bool(self.auth_key),
        }
