import sys
import json
import pandas as pd
import numpy as np
import joblib
import requests
import os
from dotenv import load_dotenv
import re

# PyQt5 imports
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMutex
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QFileDialog,
    QTextEdit, QVBoxLayout, QWidget, QHBoxLayout, QProgressBar, 
    QScrollArea, QLineEdit, QMessageBox, QSplitter, QGroupBox
)
from PyQt5.QtGui import QIcon, QFont

# Global variables
conversation_mutex = QMutex()
conversation_context = []

# --- Load ML model ---
data = joblib.load("model_raw.bin")
model = data["model"]
feats = data["features"]
LABELS = data["labels"]
LABELS_INV = {v: k for k, v in LABELS.items()}

# --- DeepSeek API configuration ---
load_dotenv()
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

def call_deepseek(messages):
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "deepseek-chat",
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 1024,
    }
    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def parse_response(content):
    text_no_headers = re.sub(r"### \*\*.*?\*\*", "", content)
    text_no_tables = re.sub(r"\|.*?\|", "", text_no_headers)
    text_clean = re.sub(r"\n{2,}", "\n\n", text_no_tables).strip()
    return text_clean

class AnalysisThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    result = pyqtSignal(dict)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        self.log.emit("Reading uploaded file...")
        self.progress.emit(10)

        try:
            with open(self.file_path, 'r') as f:
                malware_json = json.load(f)
        except Exception as e:
            self.log.emit(f"Error reading file: {e}")
            return

        # --- Feature extraction ---
        self.log.emit("Preparing features for ML model...")
        input_dict = {
            "sample_id": malware_json.get("sample_id", ""),
            "file_create": malware_json.get("rollups", {}).get("file_create", 0),
            "file_delete": malware_json.get("rollups", {}).get("file_delete", 0),
            "file_modify": malware_json.get("rollups", {}).get("file_modify", 0),
            "folder_create": malware_json.get("rollups", {}).get("folder_create", 0),
            "folder_delete": malware_json.get("rollups", {}).get("folder_delete", 0),
            "reg_set": malware_json.get("rollups", {}).get("reg_set", 0),
            "reg_delete": malware_json.get("rollups", {}).get("reg_delete", 0),
            "dns_query": malware_json.get("rollups", {}).get("dns_query", 0),
            "net_connect": malware_json.get("rollups", {}).get("net_connect", 0),
            "proc_spawn": malware_json.get("rollups", {}).get("proc_spawn", 0),
            "cpu_max": malware_json.get("rollups", {}).get("cpu_max", 0.0),
            "duration_s": malware_json.get("rollups", {}).get("duration_s", 0.0),
            "unique_exts": malware_json.get("rollups", {}).get("unique_exts", 0),
        }

        df_input = pd.DataFrame([input_dict])
        for col in ["duration_s", "cpu_max"]:
            df_input[col] = np.log1p(df_input[col])

        X_input = df_input[feats]
        y_pred_int = model.predict(X_input)
        y_pred_name = [LABELS_INV[i] for i in y_pred_int]
        predicted_label = y_pred_name[0]

        self.progress.emit(50)
        self.log.emit(f"ML Model Prediction: {predicted_label}")

        # --- DeepSeek analysis ---
        user_prompt = f"""
A malware sample has been detected with label: {predicted_label}.
Behavior JSON:

{json.dumps(malware_json, indent=2)}

Please provide:
1. Human-readable explanation of malware behavior.
2. Relevant MITRE ATT&CK techniques and tactics.
3. Recommended mitigation strategies and monitoring actions.
4. Any other potential insights.
"""
        conversation_mutex.lock()
        try:
            conversation_context.append({"role": "user", "content": user_prompt})
        finally:
            conversation_mutex.unlock()

        self.log.emit("Sending data to DeepSeek for detailed analysis...")
        self.progress.emit(70)

        api_response = call_deepseek(conversation_context)

        if "error" in api_response:
            self.log.emit(f"DeepSeek API Error: {api_response['error']}")
            return

        content = api_response['choices'][0]['message']['content']
        conversation_mutex.lock()
        try:
            conversation_context.append({"role": "assistant", "content": content})
        finally:
            conversation_mutex.unlock()

        self.progress.emit(100)
        self.log.emit("DeepSeek analysis completed.")
        self.result.emit({
            "predicted_label": predicted_label,
            "deepseek_content": parse_response(content),
            "malware_json": malware_json
        })

class AskWorker(QThread):
    response_received = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, question):
        super().__init__()
        self.question = question
    
    def run(self):
        conversation_mutex.lock()
        try:
            messages = list(conversation_context)
        finally:
            conversation_mutex.unlock()

        api_response = call_deepseek(messages)
        
        if "error" in api_response:
            self.error_occurred.emit(api_response["error"])
            return
            
        content = api_response['choices'][0]['message']['content']
        conversation_mutex.lock()
        try:
            conversation_context.append({"role": "assistant", "content": content})
        finally:
            conversation_mutex.unlock()
        
        self.response_received.emit(self.question, content)

class SunflowerApp(QMainWindow):
    update_response_signal = pyqtSignal(str, str)
    update_progress_signal = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🌻 Sunflower - Malware Behavior Analysis")
        self.setGeometry(300, 100, 1200, 900)
        self.setWindowIcon(QIcon(self.resource_path("sunflower.ico")))
        self.setStyleSheet(self._get_stylesheet())
        self.initUI()
        self.current_analysis = None
        self.initial_analysis_complete = False

    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def _get_stylesheet(self):
        return """
        /* ... (keep your existing stylesheet code) ... */
        """

    def initUI(self):
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(15, 15, 15, 15)
        self.main_layout.setSpacing(15)

        # Title
        self.title_label = QLabel("🌻 Sunflower - AI-Powered Malware Analysis")
        self.title_label.setObjectName("title")
        self.main_layout.addWidget(self.title_label)

        # Create a splitter for main content
        splitter = QSplitter(Qt.Vertical)
        
        # Upper section
        upper_group = QGroupBox("Analysis Control")
        upper_layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("Sample Selection")
        file_layout = QHBoxLayout()
        self.file_button = QPushButton("Select JSON File")
        self.file_button.clicked.connect(self.open_file_dialog)
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: #7f8c8d; font-style: italic;")
        file_layout.addWidget(self.file_button)
        file_layout.addWidget(self.file_label)
        file_group.setLayout(file_layout)
        upper_layout.addWidget(file_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        upper_layout.addWidget(self.progress_bar)
        
        # Analysis buttons
        button_layout = QHBoxLayout()
        self.analyze_button = QPushButton("Start Analysis")
        self.analyze_button.clicked.connect(self.start_analysis)
        self.finish_button = QPushButton("Finish")
        self.finish_button.clicked.connect(self.finish_analysis)
        self.finish_button.setEnabled(False)
        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.finish_button)
        upper_layout.addLayout(button_layout)
        
        upper_group.setLayout(upper_layout)
        splitter.addWidget(upper_group)
        
        # Middle section
        middle_group = QGroupBox("Analysis Results")
        middle_layout = QVBoxLayout()
        
        # Log box
        self.log_box = QTextEdit()
        self.log_box.setObjectName("log")
        self.log_box.setReadOnly(True)
        middle_layout.addWidget(QLabel("Process Log:"))
        middle_layout.addWidget(self.log_box)
        
        # Results area
        self.results_content = QTextEdit()
        self.results_content.setReadOnly(True)
        middle_layout.addWidget(QLabel("Detailed Analysis:"))
        middle_layout.addWidget(self.results_content)
        
        middle_group.setLayout(middle_layout)
        splitter.addWidget(middle_group)
        
        # Lower section
        lower_group = QGroupBox("Interactive Analysis")
        lower_layout = QVBoxLayout()
        
        self.question_input = QLineEdit()
        self.question_input.setPlaceholderText("Ask DeepSeek any follow-up questions...")
        
        self.ask_button = QPushButton("Ask")
        self.ask_button.clicked.connect(self.ask_question)
        self.ask_button.setEnabled(False)
        
        qa_layout = QHBoxLayout()
        qa_layout.addWidget(self.question_input)
        qa_layout.addWidget(self.ask_button)
        lower_layout.addLayout(qa_layout)
        
        lower_group.setLayout(lower_layout)
        splitter.addWidget(lower_group)
        
        # Set splitter stretch factors
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setStretchFactor(2, 1)
        
        self.main_layout.addWidget(splitter)
        self.setCentralWidget(self.main_widget)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        # Connect signals
        self.update_response_signal.connect(self._update_question_response)
        self.update_progress_signal.connect(self.progress_bar.setValue)

    def open_file_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File", 
            "", 
            "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.file_label.setText(file_path)
            self.current_file = file_path

    def start_analysis(self):
        if not hasattr(self, 'current_file') or not self.current_file:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return

        # Reset UI for new analysis
        self.log_box.clear()
        self.results_content.clear()
        self.question_input.clear()
        self.analyze_button.setEnabled(False)
        self.finish_button.setEnabled(False)
        self.ask_button.setEnabled(False)
        self.initial_analysis_complete = False
        self.statusBar().showMessage("Analyzing...")
        self.update_progress_signal.emit(0)

        # Clear conversation context for new analysis
        conversation_mutex.lock()
        conversation_context.clear()
        conversation_mutex.unlock()

        self.analysis_thread = AnalysisThread(self.current_file)
        self.analysis_thread.progress.connect(self._handle_progress_update)
        self.analysis_thread.log.connect(self.log_box.append)
        self.analysis_thread.result.connect(self.display_results)
        self.analysis_thread.start()

    def _handle_progress_update(self, value):
        if not self.initial_analysis_complete and value >= 80:
            value = 80
        self.update_progress_signal.emit(value)

    def display_results(self, result):
        self.current_analysis = result
        self.initial_analysis_complete = True
        self.results_content.setHtml(
            f"<h3>ML Prediction</h3>"
            f"<p style='background-color:#e8f4f8; padding:8px; border-radius:4px;'>{result['predicted_label']}</p>"
            f"<h3>DeepSeek Analysis</h3>"
            f"<div style='background-color:#f8f8f8; padding:8px; border-radius:4px;'>{result['deepseek_content']}</div>"
        )
        self.analyze_button.setEnabled(True)
        self.finish_button.setEnabled(True)
        self.ask_button.setEnabled(True)
        self.statusBar().showMessage("Initial analysis complete - you may ask follow-up questions")

    def ask_question(self):
        question = self.question_input.text().strip()
        if not question:
            return

        if not self.current_analysis:
            QMessageBox.warning(self, "Error", "No active analysis to ask about.")
            return

        self.log_box.append(f"\n[User] {question}")
        self.statusBar().showMessage("Consulting DeepSeek...")
        self.question_input.setEnabled(False)
        self.ask_button.setEnabled(False)
        
        conversation_mutex.lock()
        try:
            conversation_context.append({"role": "user", "content": question})
        finally:
            conversation_mutex.unlock()
        
        self.ask_worker = AskWorker(question)
        self.ask_worker.response_received.connect(self._update_question_response)
        self.ask_worker.error_occurred.connect(self._handle_ask_error)
        self.ask_worker.start()

    def _handle_ask_error(self, error_msg):
        self.log_box.append(f"[Error] {error_msg}")
        self.question_input.setEnabled(True)
        self.ask_button.setEnabled(True)
        self.statusBar().showMessage("Error occurred")

    def _update_question_response(self, question, response):
        current_html = self.results_content.toHtml()
        new_section = (
            f"<h3>Follow-up Question</h3>"
            f"<p style='background-color:#f0f0f0; padding:8px; border-radius:4px;'>{question}</p>"
            f"<h3>DeepSeek Response</h3>"
            f"<div style='background-color:#f8f8f8; padding:8px; border-radius:4px;'>{parse_response(response)}</div>"
        )
        self.results_content.setHtml(f"{current_html}<hr/>{new_section}")
        self.question_input.clear()
        self.question_input.setEnabled(True)
        self.ask_button.setEnabled(True)
        self.statusBar().showMessage("Response received - you may ask another question")

    def finish_analysis(self):
        self.update_progress_signal.emit(100)
        
        QMessageBox.information(
            self, 
            "Analysis Complete",
            f"<b>Final Prediction:</b><br/>{self.current_analysis['predicted_label']}<br/><br/>"
            "You can now upload a new file for analysis.",
        )
        
        # Reset for new analysis
        self.file_label.setText("No file selected")
        self.current_file = None
        self.current_analysis = None
        self.initial_analysis_complete = False
        self.log_box.clear()
        self.results_content.clear()
        self.question_input.clear()
        self.analyze_button.setEnabled(True)
        self.finish_button.setEnabled(False)
        self.ask_button.setEnabled(False)
        self.statusBar().showMessage("Ready")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SunflowerApp()
    window.show()
    sys.exit(app.exec_())