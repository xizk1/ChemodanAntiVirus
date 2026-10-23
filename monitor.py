import threading
try:
    import psutil
except ImportError:
    psutil = None

SUSPICIOUS_PROC = {
    "mimikatz": 10, "xmrig": 9, "nc": 6, "ncat": 6,
    "psexec": 7, "procdump": 8, "wce": 9, "gsecdump": 8,
}


class ProcessMonitor(threading.Thread):
    def __init__(self, on_detect, interval=2.0):
        super().__init__(daemon=True)
        self.on_detect = on_detect
        self.interval = interval
        self._stop = threading.Event()
        self.seen = set()
        if psutil:
            for p in psutil.process_iter(["pid"]):
                try:
                    self.seen.add(p.pid)
                except Exception:
                    pass

    def stop(self):
        self._stop.set()

    def run(self):
        if not psutil:
            return
        while not self._stop.wait(self.interval):
            try:
                for p in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        if p.pid in self.seen:
                            continue
                        self.seen.add(p.pid)
                        name = (p.info.get("name") or "").lower()
                        cmd = " ".join(p.info.get("cmdline") or []).lower()
                        for bad in SUSPICIOUS_PROC:
                            if bad in name or bad in cmd:
                                self.on_detect(p.pid, name, cmd, bad)
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass
