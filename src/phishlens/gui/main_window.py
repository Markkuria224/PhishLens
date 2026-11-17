"""Main desktop interface for PhishLens."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QHeaderView,
    QProgressBar,
    QScrollArea,
)

from phishlens.core.normalizer import normalize_url, NormalizationError
from phishlens.core.analyzer import analyze_url
from phishlens.core.scoring import compute_score


class AnalysisWorker(QObject):
    """Perform URL analysis outside the GUI thread."""

    result_ready = Signal(dict)
    error_occurred = Signal(str)
    completed = Signal()

    def __init__(self, original_url: str):
        super().__init__()
        self.original_url = original_url

    @Slot()
    def run(self):
        try:
            normalized_url = normalize_url(self.original_url)
            findings = analyze_url(normalized_url)
            assessment = compute_score(findings)

            result = {
                "original_url": self.original_url,
                "normalized_url": normalized_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "score": assessment["score"],
                "level": assessment["level"],
                "findings": assessment["findings"],
                "explanation": assessment["explanation"],
                "score_breakdown": assessment["score_breakdown"],
            }

            self.result_ready.emit(result)

        except NormalizationError as exc:
            self.error_occurred.emit(str(exc))

        except Exception as exc:
            self.error_occurred.emit(
                f"An unexpected analysis error occurred: {exc}"
            )

        finally:
            self.completed.emit()


class MainWindow(QMainWindow):
    """Main PhishLens application window."""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("PhishLens - Local URL Threat Analysis")
        self.resize(1000, 760)
        self.setMinimumSize(760, 600)

        self.current_result = None
        self.analysis_thread = None
        self.analysis_worker = None

        self._build_interface()
        self._apply_theme()

    def _build_interface(self):
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        content = QWidget()
        scroll_area.setWidget(content)

        self.setCentralWidget(scroll_area)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 24, 28, 20)
        layout.setSpacing(15)

        # Header
        header = QHBoxLayout()

        title = QLabel("PhishLens")
        title.setObjectName("title")

        subtitle = QLabel("LOCAL URL THREAT ANALYSIS")
        subtitle.setObjectName("subtitle")

        header.addWidget(title)
        header.addStretch()
        header.addWidget(subtitle)

        layout.addLayout(header)

        # URL input
        layout.addWidget(QLabel("ENTER URL"))

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(
            "Enter a URL to analyze, e.g. https://example.com"
        )
        self.url_input.returnPressed.connect(self.start_analysis)

        layout.addWidget(self.url_input)

        # Buttons
        buttons = QHBoxLayout()

        self.analyze_button = QPushButton("ANALYZE URL")
        self.analyze_button.setObjectName("primary")
        self.analyze_button.clicked.connect(self.start_analysis)

        self.clear_button = QPushButton("CLEAR")
        self.clear_button.clicked.connect(self.clear_results)

        buttons.addWidget(self.analyze_button)
        buttons.addWidget(self.clear_button)

        layout.addLayout(buttons)

        # Progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()

        layout.addWidget(self.progress)

        # Risk assessment
        layout.addWidget(QLabel("RISK ASSESSMENT"))

        risk_layout = QHBoxLayout()

        self.score_label = QLabel("-- / 100")
        self.score_label.setObjectName("score")

        self.level_label = QLabel("AWAITING ANALYSIS")
        self.level_label.setObjectName("risk")

        risk_layout.addWidget(self.score_label)
        risk_layout.addStretch()
        risk_layout.addWidget(self.level_label)

        layout.addLayout(risk_layout)

        # Findings
        layout.addWidget(QLabel("DETECTION FINDINGS"))

        self.findings_table = QTableWidget(0, 3)
        self.findings_table.setHorizontalHeaderLabels(
            ["RULE ID", "FINDING", "SEVERITY"]
        )

        self.findings_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.findings_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self.findings_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )

        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )
        self.findings_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )
        self.findings_table.itemSelectionChanged.connect(
            self.show_finding_details
        )

        layout.addWidget(self.findings_table)

        # Finding details
        layout.addWidget(QLabel("FINDING DETAILS"))

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(
            "Select a finding to inspect its description and evidence."
        )
        self.details.setMaximumHeight(120)

        layout.addWidget(self.details)

        # Explanation
        layout.addWidget(QLabel("ASSESSMENT EXPLANATION"))

        self.explanation = QLabel(
            "Enter a URL above to begin local analysis."
        )
        self.explanation.setWordWrap(True)
        self.explanation.setObjectName("explanation")

        layout.addWidget(self.explanation)

        # Export
        self.export_button = QPushButton("EXPORT RESULTS TO JSON")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_json)

        layout.addWidget(self.export_button)

        layout.addStretch()

        # Footer
        footer = QLabel(
            "● LOCAL ANALYSIS ONLY     |     PhishLens"
        )
        footer.setObjectName("footer")

        layout.addWidget(footer)

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #10141d;
                color: #e5e7eb;
                font-family: Segoe UI;
                font-size: 10pt;
            }

            QLabel#title {
                color: #38bdf8;
                font-size: 27pt;
                font-weight: bold;
            }

            QLabel#subtitle {
                color: #94a3b8;
                font-size: 9pt;
                letter-spacing: 2px;
            }

            QLabel#score {
                color: #38bdf8;
                font-size: 30pt;
                font-weight: bold;
            }

            QLabel#risk {
                color: #facc15;
                font-size: 17pt;
                font-weight: bold;
            }

            QLabel#footer {
                color: #22c55e;
                padding-top: 10px;
            }

            QLabel#explanation {
                color: #cbd5e1;
                padding: 8px;
                background-color: #1e293b;
                border-radius: 6px;
            }

            QLineEdit, QTextEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 10px;
                color: white;
            }

            QLineEdit:focus, QTextEdit:focus {
                border: 1px solid #38bdf8;
            }

            QPushButton {
                background-color: #334155;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 11px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #475569;
            }

            QPushButton:disabled {
                background-color: #1e293b;
                color: #64748b;
            }

            QPushButton#primary {
                background-color: #0284c7;
            }

            QPushButton#primary:hover {
                background-color: #0369a1;
            }

            QTableWidget {
                background-color: #1e293b;
                alternate-background-color: #253449;
                border: 1px solid #334155;
                gridline-color: #334155;
                selection-background-color: #075985;
            }

            QHeaderView::section {
                background-color: #263449;
                color: #38bdf8;
                padding: 8px;
                border: none;
                font-weight: bold;
            }

            QProgressBar {
                background-color: #1e293b;
                border: none;
                border-radius: 4px;
                height: 5px;
            }

            QProgressBar::chunk {
                background-color: #38bdf8;
            }
        """)

    def start_analysis(self):
        if self.analysis_thread is not None:
            return

        raw_url = self.url_input.text().strip()

        if not raw_url:
            QMessageBox.warning(
                self,
                "Missing URL",
                "Please enter a URL before starting analysis."
            )
            return

        self.analyze_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        self.export_button.setEnabled(False)

        self.progress.show()
        self.explanation.setText("Analyzing URL locally...")

        thread = QThread(self)
        worker = AnalysisWorker(raw_url)

        worker.moveToThread(thread)

        thread.started.connect(worker.run)

        worker.result_ready.connect(self.display_results)
        worker.error_occurred.connect(self.display_error)

        worker.completed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)

        thread.finished.connect(self.analysis_finished)
        thread.finished.connect(thread.deleteLater)

        self.analysis_thread = thread
        self.analysis_worker = worker

        thread.start()

    @Slot(dict)
    def display_results(self, result):
        self.current_result = result

        self.score_label.setText(
            f'{result["score"]} / 100'
        )

        self.level_label.setText(
            result["level"].upper() + " RISK"
        )

        self.findings_table.setRowCount(0)
        self.details.clear()

        for finding in result["findings"]:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)

            self.findings_table.setItem(
                row, 0, QTableWidgetItem(finding["rule_id"])
            )
            self.findings_table.setItem(
                row, 1, QTableWidgetItem(finding["title"])
            )
            self.findings_table.setItem(
                row, 2, QTableWidgetItem(finding["severity"].upper())
            )

        self.explanation.setText(result["explanation"])

        self.export_button.setEnabled(True)

        if not result["findings"]:
            self.details.setPlainText(
                "No heuristic findings were triggered. "
                "This does not guarantee that the URL is safe."
            )

    @Slot(str)
    def display_error(self, message):
        self.current_result = None
        self.score_label.setText("-- / 100")
        self.level_label.setText("ANALYSIS FAILED")
        self.findings_table.setRowCount(0)
        self.details.clear()
        self.explanation.setText(message)
        self.export_button.setEnabled(False)

        QMessageBox.warning(
            self,
            "Analysis Error",
            message
        )

    @Slot()
    def analysis_finished(self):
        thread = self.analysis_thread

        if isinstance(thread, QThread):
            thread.wait()

        self.progress.hide()
        self.analyze_button.setEnabled(True)
        self.clear_button.setEnabled(True)

        self.analysis_thread = None
        self.analysis_worker = None

    @Slot()
    def show_finding_details(self):
        if self.current_result is None:
            return

        row = self.findings_table.currentRow()

        if row < 0:
            return

        if row >= len(self.current_result["findings"]):
            return

        finding = self.current_result["findings"][row]

        self.details.setPlainText(
            f'Rule: {finding["rule_id"]}\n'
            f'Title: {finding["title"]}\n'
            f'Severity: {finding["severity"].upper()}\n\n'
            f'Description:\n{finding["description"]}\n\n'
            f'Evidence:\n{finding["evidence"]}'
        )

    def export_json(self):
        if self.current_result is None:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export PhishLens Assessment",
            "phishlens_assessment.json",
            "JSON Files (*.json)"
        )

        if not filename:
            return

        try:
            output_path = Path(filename)

            with output_path.open(
                "w",
                encoding="utf-8"
            ) as file:
                json.dump(
                    self.current_result,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            QMessageBox.information(
                self,
                "Export Successful",
                f"Assessment exported to:\n{output_path}"
            )

        except OSError as exc:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Could not save assessment:\n{exc}"
            )

    def clear_results(self):
        if self.analysis_thread is not None:
            return

        self.url_input.clear()
        self.score_label.setText("-- / 100")
        self.level_label.setText("AWAITING ANALYSIS")
        self.findings_table.setRowCount(0)
        self.details.clear()

        self.explanation.setText(
            "Enter a URL above to begin local analysis."
        )

        self.current_result = None
        self.export_button.setEnabled(False)

    def closeEvent(self, event):
        """Prevent closing while the analysis thread is running."""
        if self.analysis_thread is not None:
            QMessageBox.information(
                self,
                "Analysis in Progress",
                "Please wait for the current analysis to finish "
                "before closing PhishLens."
            )
            event.ignore()
            return

        event.accept()
