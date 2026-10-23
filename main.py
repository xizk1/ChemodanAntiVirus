import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from scanner import Scanner
from quarantine import Quarantine
from monitor import ProcessMonitor
from signature_db import SignatureDB


class ChemodanAntiVirusApp:
    COLORS = {
        "bg": "#0d1117", "panel": "#161b22", "fg": "#c9d1d9",
        "accent": "#58a6ff", "ok": "#3fb950", "warn": "#d29922",
        "bad": "#f85149", "muted": "#8b949e",
    }

    def __init__(self, root):
        self.root = root
        self.root.title("🧳 ChemodanAntiVirus")
        self.root.geometry("1150x740")
        self.root.configure(bg=self.COLORS["bg"])

        self.quarantine = Quarantine()
        self.sigdb = SignatureDB(log_cb=self._log_safe)
        self.scanner = Scanner(sigdb=self.sigdb, log_cb=self._log_safe)
        self.monitor = ProcessMonitor(self._on_proc_detect)

        self.scan_thread = None
        self.target_path = tk.StringVar(value="")
        self.auto_quarantine = tk.BooleanVar(value=True)

        self._build_style()
        self._build_ui()
        self._refresh_quarantine()
        self.monitor.start()
        self._log_safe(f"Сигнатуры: {self.sigdb.stats()}")

    # ---------- Стиль ----------
    def _build_style(self):
        s = ttk.Style()
        s.theme_use("clam")
        c = self.COLORS
        s.configure(".", background=c["bg"], foreground=c["fg"],
                    fieldbackground=c["panel"], borderwidth=0)
        s.configure("TFrame", background=c["bg"])
        s.configure("Panel.TFrame", background=c["panel"])
        s.configure("TLabel", background=c["bg"], foreground=c["fg"],
                    font=("Segoe UI", 10))
        s.configure("Title.TLabel", font=("Segoe UI", 16, "bold"),
                    foreground=c["accent"])
        s.configure("TButton", font=("Segoe UI", 10, "bold"),
                    background=c["accent"], foreground="#000",
                    padding=8, borderwidth=0)
        s.map("TButton", background=[("active", "#79c0ff")])
        s.configure("Danger.TButton", background=c["bad"])
        s.map("Danger.TButton", background=[("active", "#ff7b72")])
        s.configure("TEntry", fieldbackground=c["panel"],
                    foreground=c["fg"], padding=6)
        s.configure("Treeview", background=c["panel"], foreground=c["fg"],
                    fieldbackground=c["panel"], rowheight=26,
                    font=("Consolas", 9))
        s.configure("Treeview.Heading", background=c["bg"],
                    foreground=c["accent"], font=("Segoe UI", 10, "bold"))
        s.map("Treeview", background=[("selected", "#1f6feb")])

    # ---------- UI ----------
    def _build_ui(self):
        c = self.COLORS

        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill="x")
        ttk.Label(header, text="🧳 ChemodanAntiVirus",
                  style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="агрессивный сканер с эвристикой, YARA и карантином",
                  foreground=c["muted"]).pack(side="left", padx=16)

        path_frame = ttk.Frame(self.root, padding=(16, 4))
        path_frame.pack(fill="x")
        ttk.Entry(path_frame, textvariable=self.target_path).pack(
            side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(path_frame, text="Выбрать папку",
                   command=self._pick_dir).pack(side="left", padx=2)
        ttk.Button(path_frame, text="Выбрать файл",
                   command=self._pick_file).pack(side="left", padx=2)

        btn_frame = ttk.Frame(self.root, padding=(16, 8))
        btn_frame.pack(fill="x")
        self.btn_scan = ttk.Button(btn_frame, text="▶  Сканировать",
                                   command=self._start_scan)
        self.btn_scan.pack(side="left", padx=(0, 6))
        self.btn_stop = ttk.Button(btn_frame, text="⏹  Стоп",
                                   style="Danger.TButton",
                                   command=self._stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="🔒  В карантин выделенное",
                   command=self._quarantine_selected).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="⟳ Обновить базу",
                   command=self._refresh_signatures).pack(side="left", padx=6)

        ttk.Checkbutton(btn_frame, text="Авто-карантин MALWARE",
                        variable=self.auto_quarantine).pack(side="left", padx=16)

        prog_frame = ttk.Frame(self.root, padding=(16, 4))
        prog_frame.pack(fill="x")
        self.progress = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 4))
        self.status = ttk.Label(prog_frame, text="Готов к работе",
                                foreground=c["muted"])
        self.status.pack(anchor="w")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        self.tab_results = ttk.Frame(nb, style="Panel.TFrame")
        self.tab_quarantine = ttk.Frame(nb, style="Panel.TFrame")
        self.tab_log = ttk.Frame(nb, style="Panel.TFrame")
        nb.add(self.tab_results, text="  Результаты  ")
        nb.add(self.tab_quarantine, text="  Карантин  ")
        nb.add(self.tab_log, text="  Журнал  ")

        self._build_results_tab()
        self._build_quarantine_tab()
        self._build_log_tab()

    def _build_results_tab(self):
        cols = ("verdict", "score", "path", "reason")
        self.tree = ttk.Treeview(self.tab_results, columns=cols, show="headings")
        for col, w, title in [
            ("verdict", 100, "Вердикт"), ("score", 70, "Score"),
            ("path", 380, "Файл"), ("reason", 420, "Причина"),
        ]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("MALWARE", foreground=self.COLORS["bad"])
        self.tree.tag_configure("SUSPICIOUS", foreground=self.COLORS["warn"])
        self.tree.tag_configure("CLEAN", foreground=self.COLORS["ok"])
        self.tree.tag_configure("ERROR", foreground=self.COLORS["muted"])
        vsb = ttk.Scrollbar(self.tab_results, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _build_quarantine_tab(self):
        cols = ("qid", "original", "time", "size")
        self.qtree = ttk.Treeview(self.tab_quarantine, columns=cols, show="headings")
        for col, w, title in [
            ("qid", 160, "ID"), ("original", 420, "Исходный путь"),
            ("time", 180, "Дата"), ("size", 100, "Размер"),
        ]:
            self.qtree.heading(col, text=title)
            self.qtree.column(col, width=w, anchor="w")
        self.qtree.pack(side="left", fill="both", expand=True)
        bar = ttk.Frame(self.tab_quarantine, style="Panel.TFrame")
        bar.pack(side="right", fill="y", padx=8, pady=8)
        ttk.Button(bar, text="↩ Восстановить",
                   command=self._restore_selected).pack(fill="x", pady=4)
        ttk.Button(bar, text="🗑 Удалить", style="Danger.TButton",
                   command=self._delete_selected).pack(fill="x", pady=4)
        ttk.Button(bar, text="⟳ Обновить",
                   command=self._refresh_quarantine).pack(fill="x", pady=4)

    def _build_log_tab(self):
        self.log_text = tk.Text(self.tab_log, bg=self.COLORS["panel"],
                                fg=self.COLORS["fg"], font=("Consolas", 9),
                                borderwidth=0, wrap="word")
        self.log_text.pack(fill="both", expand=True)

    # ---------- Логирование ----------
    def _log_safe(self, msg):
        try:
            self.root.after(0, lambda: self._log(msg))
        except Exception:
            pass

    def _log(self, msg):
        from datetime import datetime
        self.log_text.insert("end", f"[{datetime.now():%H:%M:%S}] {msg}\n")
        self.log_text.see("end")

    # ---------- Действия ----------
    def _pick_dir(self):
        d = filedialog.askdirectory(title="Выберите папку для сканирования")
        if d:
            self.target_path.set(d)

    def _pick_file(self):
        f = filedialog.askopenfilename(title="Выберите файл")
        if f:
            self.target_path.set(f)

    def _start_scan(self):
        path = self.target_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Ошибка", "Укажите существующий путь")
            return
        self.tree.delete(*self.tree.get_children())
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.progress["value"] = 0
        self.status.configure(text="Сканирование...")
        self._log(f"Начато сканирование: {path}")

        def worker():
            self.scanner.scan_path(path,
                                   callback=self._on_result,
                                   progress=self._on_progress)
            self.root.after(0, self._scan_done)

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.scanner.stop()
        self._log("Запрошена остановка")

    def _on_progress(self, i, fp):
        total = max(self.scanner.stats.total, 1)
        pct = (i / total) * 100
        self.root.after(0, lambda: self.progress.configure(value=pct))
        self.root.after(0, lambda: self.status.configure(
            text=f"{i}/{total} — {os.path.basename(fp)}"))

    def _on_result(self, res):
        def upd():
            reason = "; ".join(res.reasons[:3])
            self.tree.insert("", "end",
                             values=(res.verdict, res.score, res.path, reason),
                             tags=(res.verdict,))
            if res.verdict == "MALWARE":
                self._log(f"⚠ MALWARE: {res.path} — {reason}")
                if self.auto_quarantine.get():
                    try:
                        qid = self.quarantine.quarantine(res.path, res.reasons)
                        self._log(f"  → карантин {qid}")
                        self._refresh_quarantine()
                    except Exception as e:
                        self._log(f"  ! карантин не удался: {e}")
        self.root.after(0, upd)

    def _scan_done(self):
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        s = self.scanner.stats
        self.status.configure(
            text=f"Готово за {s.duration:.1f}с — проверено {s.total}, "
                 f"malware {s.malware}, suspicious {s.suspicious}")
        self.progress["value"] = 100
        self._log(f"Сканирование завершено: {s}")

    def _quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Карантин", "Выделите файлы в результатах")
            return
        count = 0
        for iid in sel:
            vals = self.tree.item(iid, "values")
            path, verdict = vals[2], vals[0]
            if verdict == "CLEAN":
                continue
            try:
                self.quarantine.quarantine(path, [vals[3]])
                self._log(f"Карантин: {path}")
                count += 1
            except Exception as e:
                self._log(f"Ошибка: {path}: {e}")
        self._refresh_quarantine()
        messagebox.showinfo("Карантин", f"Перемещено: {count}")

    def _refresh_signatures(self):
        def worker():
            self.sigdb.refresh_hashes_now()
            self._log_safe(f"База: {self.sigdb.stats()}")
        threading.Thread(target=worker, daemon=True).start()

    def _refresh_quarantine(self):
        self.qtree.delete(*self.qtree.get_children())
        for qid, meta in self.quarantine.list().items():
            self.qtree.insert("", "end", values=(
                qid, meta["original_path"],
                meta["quarantined_at"][:19],
                f"{meta.get('size', 0)} B"
            ))

    def _restore_selected(self):
        sel = self.qtree.selection()
        if not sel:
            return
        qid = self.qtree.item(sel[0], "values")[0]
        try:
            dst = self.quarantine.restore(qid)
            self._log(f"Восстановлен: {dst}")
            self._refresh_quarantine()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _delete_selected(self):
        sel = self.qtree.selection()
        if not sel:
            return
        if not messagebox.askyesno("Удалить", "Удалить навсегда?"):
            return
        qid = self.qtree.item(sel[0], "values")[0]
        self.quarantine.delete(qid)
        self._log(f"Удалён: {qid}")
        self._refresh_quarantine()

    def _on_proc_detect(self, pid, name, cmd, bad):
        msg = f"⚠ Подозрительный процесс PID={pid} name={name} (правило: {bad})"
        self.root.after(0, lambda: self._log(msg))


if __name__ == "__main__":
    root = tk.Tk()
    app = ChemodanAntiVirusApp(root)
    root.mainloop()
