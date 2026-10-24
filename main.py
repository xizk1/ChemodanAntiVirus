import sys
import os
import threading
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFileDialog, QTableWidgetItem
from PyQt5.QtGui import QIcon

# Импорты Fluent Design
from qfluentwidgets import (FluentWindow, NavigationItemPosition, SubtitleLabel, 
                            PrimaryPushButton, PushButton, LineEdit, ProgressBar, 
                            InfoBar, InfoBarPosition, TableWidget, SwitchButton, 
                            BodyLabel, setTheme, Theme, FluentIcon as FIF)

from scanner import Scanner
from quarantine import Quarantine
from signature_db import SignatureDB
from monitor import ProcessMonitor

# Класс-поток для сканирования, чтобы интерфейс не зависал
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
        
        # Включаем тёмную тему (стиль Windows 11)
        setTheme(Theme.DARK)

        self.quarantine = Quarantine()
        self.sigdb = SignatureDB(log_cb=self.log_msg)
        self.scanner = Scanner(sigdb=self.sigdb, log_cb=self.log_msg)
        self.monitor = ProcessMonitor(self.on_proc_detect)
        self.monitor.start()

        # Создаем страницы
        self.scan_page = QWidget()
        self.scan_page.setObjectName("scanPage")
        self.quar_page = QWidget()
        self.quar_page.setObjectName("quarPage")
        
        self.init_scan_page()
        self.init_quar_page()

        # Добавляем страницы в навигацию
        self.addSubInterface(self.scan_page, FIF.SEARCH, "Сканер")
        self.addSubInterface(self.quar_page, FIF.ZIP_FOLDER, "Карантин")

        # Настройка навигации (снизу)
        self.navigationInterface.setExpandWidth(200)
        self.navigationInterface.setCollapsible(False)

    def init_scan_page(self):
        layout = QVBoxLayout(self.scan_page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Заголовок
        title = SubtitleLabel("Сканирование системы")
        layout.addWidget(title)

        # Выбор пути
        path_layout = QHBoxLayout()
        self.path_edit = LineEdit()
        self.path_edit.setPlaceholderText("Выберите папку или файл для проверки...")
        path_layout.addWidget(self.path_edit)

        btn_dir = PushButton("Папка")
        btn_dir.clicked.connect(self.pick_dir)
        path_layout.addWidget(btn_dir)

        btn_file = PushButton("Файл")
        btn_file.clicked.connect(self.pick_file)
        path_layout.addWidget(btn_file)
        layout.addLayout(path_layout)

        # Кнопки управления
        action_layout = QHBoxLayout()
        self.btn_scan = PrimaryPushButton("Сканировать", icon=FIF.PLAY)
        self.btn_scan.clicked.connect(self.start_scan)
        action_layout.addWidget(self.btn_scan)

        self.btn_stop = PushButton("Стоп", icon=FIF.CANCEL)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setEnabled(False)
        action_layout.addWidget(self.btn_stop)

        self.switch_quar = SwitchButton()
        self.switch_quar.setOnText("Авто-карантин ВКЛ")
        self.switch_quar.setOffText("Авто-карантин ВЫКЛ")
        self.switch_quar.setChecked(True)
        action_layout.addWidget(self.switch_quar)
        layout.addLayout(action_layout)

        # Прогресс
        self.progress = ProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        
        self.status_label = BodyLabel("Готов к работе")
        layout.addWidget(self.status_label)

        # Таблица результатов
        self.table = TableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Вердикт", "Баллы", "Файл", "Причина"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setBorderVisible(True)
        self.table.setBorderRadius(8)
        self.table.setWordWrap(True)
        layout.addWidget(self.table)

    def init_quar_page(self):
        layout = QVBoxLayout(self.quar_page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = SubtitleLabel("Карантин")
        layout.addWidget(title)

        self.q_table = TableWidget()
        self.q_table.setColumnCount(4)
        self.q_table.setHorizontalHeaderLabels(["ID", "Исходный путь", "Дата", "Размер"])
        self.q_table.horizontalHeader().setStretchLastSection(True)
        self.q_table.setBorderVisible(True)
        self.q_table.setBorderRadius(8)
        layout.addWidget(self.q_table)

        btn_layout = QHBoxLayout()
        btn_refresh = PushButton("Обновить")
        btn_refresh.clicked.connect(self.refresh_quarantine)
        btn_layout.addWidget(btn_refresh)
        
        btn_restore = PrimaryPushButton("Восстановить выделенное")
        btn_restore.clicked.connect(self.restore_selected)
        btn_layout.addWidget(btn_restore)

        btn_delete = PushButton("Удалить навсегда")
        btn_delete.clicked.connect(self.delete_selected)
        btn_layout.addWidget(btn_delete)
        layout.addLayout(btn_layout)
        
        self.refresh_quarantine()

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
        
        # Подсветка цветом
        if res.verdict == "MALWARE":
            for col in range(4):
                self.table.item(row, col).setForeground(Qt.red)
        elif res.verdict == "SUSPICIOUS":
            for col in range(4):
                self.table.item(row, col).setForeground(Qt.yellow)

        if res.verdict == "MALWARE" and self.switch_quar.isChecked():
            try:
                self.quarantine.quarantine(res.path, res.reasons)
                self.refresh_quarantine()
            except Exception as e:
                self.log_msg(f"Ошибка карантина: {e}")

    def on_finished(self, stats):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress.setValue(100)
        self.status_label.setText(f"Готово за {stats.duration:.1f}с. Найдено угроз: {stats.malware}")
        InfoBar.success(title="Сканирование завершено", content=f"Проверено файлов: {stats.total}", parent=self)

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
            path = self.quarantine.restore(qid)
            InfoBar.success(title="Восстановлено", content=path, parent=self)
            self.refresh_quarantine()
        except Exception as e:
            InfoBar.error(title="Ошибка", content=str(e), parent=self)

    def delete_selected(self):
        selected = self.q_table.selectedItems()
        if not selected: return
        qid = self.q_table.item(selected[0].row(), 0).text()
        self.quarantine.delete(qid)
        self.refresh_quarantine()

    def on_proc_detect(self, pid, name, cmd, bad):
        # Потокобезопасный вывод уведомления
        self.show_proc_alert(pid, name, bad)

    def show_proc_alert(self, pid, name, bad):
        InfoBar.warning(
            title="Подозрительный процесс",
            content=f"{name} (PID: {pid}) сработал по правилу: {bad}",
            duration=5000,
            position=InfoBarPosition.TOP_RIGHT,
            parent=self
        )

    def log_msg(self, msg):
        print(f"[LOG] {msg}")

if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
