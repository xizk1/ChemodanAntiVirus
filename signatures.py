import re
import hashlib

# ============ ЭВРИСТИЧЕСКИЕ ПРАВИЛА ============
HEURISTIC_RULES = [
    # PowerShell / cmd abuse
    (rb"powershell(\.exe)?\s+.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}",
     "PowerShell encoded command", 9),
    (rb"powershell.*-w(indowstyle)?\s+hidden", "PowerShell hidden window", 8),
    (rb"cmd(\.exe)?\s+/c\s+.*(del|format|rd)\s+/[sq]", "Destructive cmd", 9),
    (rb"bitsadmin\s+/transfer", "BITSAdmin download", 7),
    (rb"certutil\s+-urlcache\s+-split", "Certutil download", 8),
    (rb"mshta\s+https?://", "MSHTA remote execution", 8),
    (rb"regsvr32\s+/s\s+/u\s+/i:https?://", "Regsvr32 squiblydoo", 9),
    (rb"wmic\s+process\s+call\s+create", "WMIC process creation", 7),
    # Persistence
    (rb"schtasks\s+/create.*(/sc\s+onlogon|/ru\s+system)", "Scheduled task persistence", 7),
    (rb"reg\s+add.*\\Run(Once)?\\", "Registry Run key persistence", 8),
    (rb"CurrentVersion\\Run", "Run key reference", 6),
    # Credential theft
    (rb"mimikatz", "Mimikatz reference", 10),
    (rb"sekurlsa::logonpasswords", "Mimikatz logonpasswords", 10),
    (rb"lsass\.exe.*MiniDump", "LSASS dump", 10),
    # Ransomware behavior
    (rb"vssadmin\s+delete\s+shadows", "Shadow copy deletion", 10),
    (rb"bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no", "Recovery disable", 9),
    (rb"wbadmin\s+delete\s+catalog", "Backup catalog deletion", 9),
    (rb"\.(locked|encrypted|crypt)\b.*ransom", "Ransom note pattern", 8),
    # Obfuscation
    (rb"eval\s*\(\s*(base64|atob|fromCharCode)", "JS eval obfuscation", 7),
    (rb"String\.fromCharCode\s*\(\s*\d+(,\s*\d+){10,}", "Char code obfuscation", 6),
    (rb"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "Hex escape chain", 5),
    # Network
    (rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Raw IP URL", 5),
    (rb"(?:pastebin|ngrok|transfer\.sh|anonfiles)", "Suspicious host", 7),
    # Crypto miners
    (rb"stratum\+tcp://", "Crypto miner stratum", 9),
    (rb"xmrig", "XMRig reference", 9),
    # Macros
    (rb"AutoOpen\s*\(\s*\)", "Office AutoOpen macro", 7),
    (rb"Document_Open\s*\(\s*\)", "Word Document_Open macro", 7),
]

DANGEROUS_EXT = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl",
    ".msi", ".msp", ".jar", ".lnk", ".reg", ".dll",
}

DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|jpg|jpeg|png|txt|zip|rar)\.(exe|scr|bat|cmd|vbs|js|ps1|hta)$",
    re.IGNORECASE
)

# ============ УТИЛИТЫ ============
def sha256_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()

def scan_bytes(data: bytes):
    hits = []
    for pattern, desc, weight in HEURISTIC_RULES:
        if re.search(pattern, data, re.IGNORECASE | re.DOTALL):
            hits.append((desc, weight))
    return hits
