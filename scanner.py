import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from signatures import sha256_file, scan_bytes, DANGEROUS_EXT, DOUBLE_EXT_RE
from signature_db import SignatureDB

@dataclass
class ScanResult:
    path: str
    verdict: str
    score: int = 0
    reasons: list = field(default_factory=list)
    sha256: str = ""

@dataclass
class ScanStats:
    total: int = 0
    clean: int = 0
    suspicious: int = 0
    malware: int = 0
    errors: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self):
        return self.end_time - self.start_time

class Scanner:
    MAX_FILE_SIZE = 64 * 1024 * 1024
    SUSPICIOUS_THRESHOLD = 6
    MALWARE_THRESHOLD = 12

    def __init__(self, sigdb: SignatureDB = None, log_cb=None):
        self.sigdb = sigdb or SignatureDB(log_cb=log_cb)
        self.log = log_cb or (lambda msg: None)
        self.stats = ScanStats()
        self._stop = False

    def stop(self):
        self._stop = True

    def scan_file(self, path: str) -> ScanResult:
        res = ScanResult(path=path, verdict="CLEAN")
        try:
            # Игнорируем исходники Python, чтобы не жрать самого себя
            if path.endswith(".py") or path.endswith(".spec"):
                res.verdict = "CLEAN"
                self.stats.clean += 1
                return res

            size = os.path.getsize(path)
            ext = os.path.splitext(path)[1].lower()

            if DOUBLE_EXT_RE.search(os.path.basename(path)):
                res.score += 8
                res.reasons.append("Двойное расширение")

            try:
                res.sha256 = sha256_file(path)
                known_tag = self.sigdb.lookup_hash(res.sha256)
                if known_tag:
                    res.verdict = "MALWARE"
                    res.reasons.append(f"MalwareBazaar: {known_tag}")
                    res.score = 100
                    self.stats.malware += 1
                    return res
            except (PermissionError, OSError) as e:
                res.verdict = "ERROR"
                res.reasons.append(f"Нет доступа: {e}")
                self.stats.errors += 1
                return res

            for rule_name, tags in self.sigdb.match_yara(path):
                res.score += 10
                tag_str = ",".join(tags) if tags else "no-tag"
                res.reasons.append(f"YARA: {rule_name} [{tag_str}]")

            if ext in DANGEROUS_EXT:
                res.score += 1

            if size <= self.MAX_FILE_SIZE:
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    for desc, weight in scan_bytes(data):
                        res.score += weight
                        res.reasons.append(desc)
                except (PermissionError, OSError):
                    pass

            if res.score >= self.MALWARE_THRESHOLD:
                res.verdict = "MALWARE"
                self.stats.malware += 1
            elif res.score >= self.SUSPICIOUS_THRESHOLD:
                res.verdict = "SUSPICIOUS"
                self.stats.suspicious += 1
            else:
                res.verdict = "CLEAN"
                self.stats.clean += 1

        except Exception as e:
            res.verdict = "ERROR"
            res.reasons.append(str(e))
            self.stats.errors += 1

        return res

    def scan_path(self, root: str,
                  callback: Optional[Callable[[ScanResult], None]] = None,
                  progress: Optional[Callable[[int, str], None]] = None):
        self.stats = ScanStats(start_time=time.time())
        self._stop = False

        files = []
        if os.path.isfile(root):
            files = [root]
        else:
            # Исключаем папку с самим антивирусом и системный мусор
            skip = {"$Recycle.Bin", "System Volume Information", "Windows",
                    "node_modules", ".git", "__pycache__", "data", "quarantine",
                    "ChemodanAntiVirus", "dist", "build"}
            
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in skip]
                for fn in filenames:
                    if fn.endswith((".py", ".spec", ".md", ".json", ".txt")):
                        continue # Пропускаем текстовые файлы и код
                    files.append(os.path.join(dirpath, fn))

        self.stats.total = len(files)

        for i, fp in enumerate(files):
            if self._stop:
                break
            if progress:
                progress(i, fp)
            r = self.scan_file(fp)
            if callback:
                callback(r)

        self.stats.end_time = time.time()
        return self.stats
