import sys
import os
import threading
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFileDialog, QTableWidgetItem, QDialog, QLabel
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent

from qfluentwidgets import (FluentWindow, SubtitleLabel, 
                            PrimaryPushButton, PushButton, LineEdit, ProgressBar, 
                            InfoBar, InfoBarPosition, TableWidget, SwitchButton, 
                            BodyLabel, setTheme, Theme, FluentIcon as FIF, ScrollArea)

from scanner import Scanner
from quarantine import Quarantine
from signature_db import SignatureDB
from monitor import ProcessMonitor

# --- Пасхалка: Окно с картинкой ---
class EasterEggDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Секрет")
        self.setFixedSize(400, 400)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        
        layout = QVBoxLayout(self)
        img_path = os.path.join("sysQuarantine", "shb022", "other", "chemodan", "ok.png")
        if os.path.exists(img_path):
            label = QLabel(self)
            pixmap = QPixmap(img_path)
            label.setPixmap(pixmap.scaled(400, 400, Qt.KeepAspectRatio))
            layout.addWidget(label)
        
        # Закрыть через 10 секунд
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(10000, self.close)

# --- Поток сканирования ---
class ScanThread(QThread):
    result_signal = pyqtSignal(object)
    progress_signal = pyqtSignal(int, str)
    finished_signal = pyqtSignal(object)

    def __init__(self, scanner, path):
        super().__init__()
        self.scanner = scanner
        self.path = path

    def run(self):
        stats = self.scanner.scan_path(
            self.path, 
            callback=lambda r: self.result_signal.emit(r),
            progress=lambda i, f: self.progress_signal.emit(i, f)
        )
        self.finished_signal.emit(stats)

class MainWindow(FluentWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Chemodan AntiVirus")
        self.resize(1000, 700)
        setTheme(Theme.DARK)

        # Медиаплеер для пасхалки
        self.player = QMediaPlayer()
        music_path = os.path.join("sysQuarantine", "shb022", "other", "chemodan", "omaigad.mp3")
        if os.path.exists(music_path):
            self.player.setMedia(QMediaContent(QUrl.fromLocalFile(os.path.abspath(music_path))))

        self.quarantine = Quarantine()
        self.sigdb = SignatureDB(log_cb=self.log_msg)
        self.scanner = Scanner(sigdb=self.sigdb, log_cb=self.log_msg)
        self.monitor = ProcessMonitor(self.on_proc_detect)
        self.monitor.start()

        self.scan_page = QWidget()
        self.scan_page.setObjectName("scanPage")
        self.quar_page = QWidget()
        self.quar_page.setObjectName("quarPage")
        self.dev_page = QWidget()
        self.dev_page.setObjectName("devPage")
        
        self.init_scan_page()
        self.init_quar_page()
        self.init_dev_page()

        self.addSubInterface(self.scan_page, FIF.SEARCH, "Сканер")
        self.addSubInterface(self.quar_page, FIF.ZIP_FOLDER, "Карантин")
        self.addSubInterface(self.dev_page, FIF.DEVELOPER_TOOLS, "Разработчики")

        self.navigationInterface.setExpandWidth(200)

    def init_scan_page(self):
        layout = QVBoxLayout(self.scan_page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        layout.addWidget(SubtitleLabel("Сканирование системы"))

        path_layout = QHBoxLayout()
        self.path_edit = LineEdit()
        self.path_edit.setPlaceholderText("Выберите папку или файл...")
        path_layout.addWidget(self.path_edit)
        btn_dir = PushButton("Папка")
        btn_dir.clicked.connect(self.pick_dir)
        path_layout.addWidget(btn_dir)
        btn_file = PushButton("Файл")
        btn_file.clicked.connect(self.pick_file)
        path_layout.addWidget(btn_file)
        layout.addLayout(path_layout)

        action_layout = QHBoxLayout()
        self.btn_scan = PrimaryPushButton("Сканировать", icon=FIF.PLAY)
        self.btn_scan.clicked.connect(self.start_scan)
        action_layout.addWidget(self.btn_scan)
        
        self.btn_stop = PushButton("Стоп", icon=FIF.CANCEL)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setEnabled(False)
        action_layout.addWidget(self.btn_stop)

        self.switch_quar = SwitchButton()
        self.switch_quar.setOnText("Авто-карантин")
        self.switch_quar.setChecked(True)
        action_layout.addWidget(self.switch_quar)
        layout.addLayout(action_layout)

        self.progress = ProgressBar()
        layout.addWidget(self.progress)
        self.status_label = BodyLabel("Готов к работе")
        layout.addWidget(self.status_label)

        self.table = TableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Вердикт", "Баллы", "Файл", "Причина"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def init_quar_page(self):
        layout = QVBoxLayout(self.quar_page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        layout.addWidget(SubtitleLabel("Карантин"))

        self.q_table = TableWidget()
        self.q_table.setColumnCount(4)
        self.q_table.setHorizontalHeaderLabels(["ID", "Исходный путь", "Дата", "Размер"])
        self.q_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.q_table)

        btn_layout = QHBoxLayout()
        btn_refresh = PushButton("Обновить")
        btn_refresh.clicked.connect(self.refresh_quarantine)
        btn_layout.addWidget(btn_refresh)
        btn_restore = PrimaryPushButton("Восстановить")
        btn_restore.clicked.connect(self.restore_selected)
        btn_layout.addWidget(btn_restore)
        btn_delete = PushButton("Удалить")
        btn_delete.clicked.connect(self.delete_selected)
        btn_layout.addWidget(btn_delete)
        layout.addLayout(btn_layout)
        self.refresh_quarantine()

    def init_dev_page(self):
        layout = QVBoxLayout(self.dev_page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        layout.addWidget(SubtitleLabel("Разработчики"))
        layout.addWidget(BodyLabel("Нажмите дважды на биографию, чтобы открыть секрет..."))

        # Блок x1zkesDEV
        self.dev1 = QLabel("x1zkesDEV (xizk1)\n\nНаписал интерфейс, подключение к серверам MalwareBazaar, добавил систему карантина")
        self.dev1.setFont(QFont("Segoe UI", 12))
        self.dev1.setWordWrap(True)
        self.dev1.setStyleSheet("background: #2b2b2b; padding: 15px; border-radius: 8px;")
        self.dev1.mouseDoubleClickEvent = self.trigger_easter_egg
        layout.addWidget(self.dev1)

        # Блок Deepseek
        self.dev2 = QLabel("Deepseek\n\nНаписал сканер вирусов, мониторинг файлов, нашел сигнатуры")
        self.dev2.setFont(QFont("Segoe UI", 12))
        self.dev2.setWordWrap(True)
        self.dev2.setStyleSheet("background: #2b2b2b; padding: 15px; border-radius: 8px;")
        self.dev2.mouseDoubleClickEvent = self.trigger_easter_egg
        layout.addWidget(self.dev2)

        layout.addStretch()

    def trigger_easter_egg(self, event):
        if os.path.exists(os.path.join("sysQuarantine", "shb022", "other", "chemodan", "omaigad.mp3")):
            self.player.play()
        
        dialog = EasterEggDialog(self)
        dialog.show()

    def pick_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if d: self.path_edit.setText(d)

    def pick_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if f: self.path_edit.setText(f)

    def start_scan(self):
        path = self.path_edit.text().strip()
        if not path or not os.path.exists(path):
            InfoBar.error(title="Ошибка", content="Укажите существующий путь", parent=self)
            return

        self.table.setRowCount(0)
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)
        self.status_label.setText("Сканирование...")

        self.thread = ScanThread(self.scanner, path)
        self.thread.result_signal.connect(self.on_result)
        self.thread.progress_signal.connect(self.on_progress)
        self.thread.finished_signal.connect(self.on_finished)
        self.thread.start()

    def stop_scan(self):
        self.scanner.stop()

    def on_progress(self, i, fp):
        total = max(self.scanner.stats.total, 1)
        self.progress.setValue(int((i / total) * 100))
        self.status_label.setText(f"Проверка: {os.path.basename(fp)}")

    def on_result(self, res):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(res.verdict))
        self.table.setItem(row, 1, QTableWidgetItem(str(res.score)))
        self.table.setItem(row, 2, QTableWidgetItem(res.path))
        self.table.setItem(row, 3, QTableWidgetItem("; ".join(res.reasons[:3])))
        
        if res.verdict == "MALWARE":
            for col in range(4):
                self.table.item(row, col).setForeground(Qt.red)
            InfoBar.error(title="Найден вирус!", content=res.path, position=InfoBarPosition.TOP_RIGHT, duration=3000, parent=self)
        elif res.verdict == "SUSPICIOUS":
            for col in range(4):
                self.table.item(row, col).setForeground(Qt.yellow)

        if res.verdict == "MALWARE" and self.switch_quar.isChecked():
            try:
                self.quarantine.quarantine(res.path, res.reasons)
                self.refresh_quarantine()
            except Exception as e:
                pass

    def on_finished(self, stats):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress.setValue(100)
        self.status_label.setText(f"Готово за {stats.duration:.1f}с. Угроз: {stats.malware}")
        InfoBar.success(title="Готово", content=f"Проверено: {stats.total}", parent=self)

    def refresh_quarantine(self):
        self.q_table.setRowCount(0)
        for qid, meta in self.quarantine.list().items():
            row = self.q_table.rowCount()
            self.q_table.insertRow(row)
            self.q_table.setItem(row, 0, QTableWidgetItem(qid))
            self.q_table.setItem(row, 1, QTableWidgetItem(meta["original_path"]))
            self.q_table.setItem(row, 2, QTableWidgetItem(meta["quarantined_at"][:19]))
            self.q_table.setItem(row, 3, QTableWidgetItem(f"{meta.get('size', 0)} B"))

    def restore_selected(self):
        selected = self.q_table.selectedItems()
        if not selected: return
        qid = self.q_table.item(selected[0].row(), 0).text()
        try:
            self.quarantine.restore(qid)
            self.refresh_quarantine()
            InfoBar.success(title="Восстановлено", content="Файл возвращен", parent=self)
        except Exception as e:
            InfoBar.error(title="Ошибка", content=str(e), parent=self)

    def delete_selected(self):
        selected = self.q_table.selectedItems()
        if not selected: return
        qid = self.q_table.item(selected[0].row(), 0).text()
        self.quarantine.delete(qid)
        self.refresh_quarantine()

    def on_proc_detect(self, pid, name, cmd, bad):
        self.show_proc_alert(pid, name, bad)

    def show_proc_alert(self, pid, name, bad):
        InfoBar.warning(title="Подозрительный процесс", content=f"{name} (PID: {pid}). Правило: {bad}", duration=5000, position=InfoBarPosition.TOP_RIGHT, parent=self)

    def log_msg(self, msg):
        print(f"[LOG] {msg}")

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
