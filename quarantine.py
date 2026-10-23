import os
import shutil
import json
import hashlib
from datetime import datetime

QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), "quarantine")
INDEX_FILE = os.path.join(QUARANTINE_DIR, "_index.json")


class Quarantine:
    def __init__(self):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(INDEX_FILE):
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                self.index = json.load(f)
        else:
            self.index = {}

    def _save(self):
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(self.index, f, indent=2, ensure_ascii=False)

    def quarantine(self, path: str, reasons: list) -> str:
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        qid = hashlib.sha256(
            (path + datetime.now().isoformat()).encode()
        ).hexdigest()[:16]
        dest = os.path.join(QUARANTINE_DIR, qid + ".qtn")
        try:
            shutil.move(path, dest)
        except OSError:
            shutil.copy2(path, dest)
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.chmod(dest, 0o400)
        except OSError:
            pass
        self.index[qid] = {
            "original_path": path,
            "quarantined_at": datetime.now().isoformat(),
            "reasons": reasons,
            "size": os.path.getsize(dest),
        }
        self._save()
        return qid

    def restore(self, qid: str) -> str:
        if qid not in self.index:
            raise KeyError(qid)
        meta = self.index[qid]
        src = os.path.join(QUARANTINE_DIR, qid + ".qtn")
        dst = meta["original_path"]
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        shutil.move(src, dst)
        os.chmod(dst, 0o644)
        del self.index[qid]
        self._save()
        return dst

    def delete(self, qid: str):
        src = os.path.join(QUARANTINE_DIR, qid + ".qtn")
        if os.path.exists(src):
            try:
                os.chmod(src, 0o600)
            except OSError:
                pass
            os.remove(src)
        self.index.pop(qid, None)
        self._save()

    def list(self) -> dict:
        return self.index
