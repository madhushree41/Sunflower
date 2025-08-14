from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QFileDialog,
    QTextEdit, QVBoxLayout, QWidget, QHBoxLayout, QProgressBar, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import sys
import time

class AnalysisThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)

    def run(self):
        for i in range(1, 101):
            time.sleep(0.05)  # Simulate analysis task
            self.progress.emit(i)
            self.log.emit(f"Analysis Step {i} completed.")

class SunflowerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sunflower - Malware Behavior Analysis")
        self.setGeometry(300, 100, 800, 600)

        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()

        # Title
        self.title_label = QLabel("🌻 Sunflower - AI-Powered Malware Analysis")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        main_layout.addWidget(self.title_label)

        # File Selection Button
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.file_button = QPushButton("Select File")
        self.file_button.clicked.connect(self.open_file_dialog)
        file_layout.addWidget(self.file_button)
        file_layout.addWidget(self.file_label)
        main_layout.addLayout(file_layout)

        # Start Analysis Button
        self.analyze_button = QPushButton("Start Analysis")
        self.analyze_button.clicked.connect(self.start_analysis)
        main_layout.addWidget(self.analyze_button)

        # Progress Bar
        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)

        # Logs Text Box
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        main_layout.addWidget(self.log_box)

        # Behavior Table (Malware classification results)
        self.behavior_table = QTableWidget(0, 2)
        self.behavior_table.setHorizontalHeaderLabels(["Behavior", "Status"])
        main_layout.addWidget(self.behavior_table)

        # Set main layout
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def open_file_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "Executables (*.exe);;All Files (*)")
        if file_path:
            self.file_label.setText(file_path)

    def start_analysis(self):
        self.analysis_thread = AnalysisThread()
        self.analysis_thread.progress.connect(self.update_progress)
        self.analysis_thread.log.connect(self.append_log)
        self.analysis_thread.finished.connect(self.analysis_complete)
        self.analysis_thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def append_log(self, message):
        self.log_box.append(message)

    def analysis_complete(self):
        self.append_log("Analysis Complete! Displaying behavior results...")

        # Simulate detected behaviors
        behaviors = [("File Deletion", "Detected"), ("Registry Modification", "Clean"), ("Network Beaconing", "Detected")]
        self.behavior_table.setRowCount(len(behaviors))

        for row, (behavior, status) in enumerate(behaviors):
            self.behavior_table.setItem(row, 0, QTableWidgetItem(behavior))
            self.behavior_table.setItem(row, 1, QTableWidgetItem(status))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SunflowerApp()
    window.show()
    sys.exit(app.exec_())
