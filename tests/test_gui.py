"""Tests for the PhishLens desktop GUI."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from phishlens.gui.main_window import MainWindow


@pytest.fixture(scope="session")
def app():
    """Create one QApplication instance for the test session."""
    application = QApplication.instance()

    if application is None:
        application = QApplication([])

    yield application


@pytest.fixture
def window(app):
    """Create a fresh MainWindow for each test."""
    from PySide6.QtCore import QElapsedTimer
    from PySide6.QtTest import QTest

    main_window = MainWindow()
    main_window.show()

    yield main_window

    if main_window.analysis_thread is not None:
        timer = QElapsedTimer()
        timer.start()

        while (
            main_window.analysis_thread is not None
            and timer.elapsed() < 5000
        ):
            QTest.qWait(10)

    if main_window.analysis_thread is None:
        main_window.close()
    else:
        pytest.fail("Analysis thread did not finish within 5 seconds.")

class TestMainWindow:

    def test_window_initializes(self, window):
        assert window.windowTitle() == (
            "PhishLens - Local URL Threat Analysis"
        )

    def test_initial_interface_state(self, window):
        assert window.url_input.text() == ""
        assert window.score_label.text() == "-- / 100"
        assert window.level_label.text() == "AWAITING ANALYSIS"
        assert window.findings_table.rowCount() == 0
        assert window.current_result is None
        assert not window.export_button.isEnabled()
        assert not window.progress.isVisible()

    def test_display_results(self, window):
        result = {
            "original_url": "http://example.test",
            "normalized_url": "http://example.test",
            "timestamp": "2026-11-16T18:00:00+00:00",
            "score": 60,
            "level": "high",
            "findings": [
                {
                    "rule_id": "URL_001",
                    "title": "IP Address Hostname",
                    "severity": "high",
                    "description": "The URL uses an IP address.",
                    "evidence": "192.168.1.1",
                }
            ],
            "explanation": "A suspicious URL was detected.",
            "score_breakdown": {},
        }

        window.display_results(result)

        assert window.current_result == result
        assert window.score_label.text() == "60 / 100"
        assert window.level_label.text() == "HIGH RISK"
        assert window.findings_table.rowCount() == 1
        assert window.findings_table.item(0, 0).text() == "URL_001"
        assert window.findings_table.item(0, 1).text() == (
            "IP Address Hostname"
        )
        assert window.findings_table.item(0, 2).text() == "HIGH"
        assert window.export_button.isEnabled()

    def test_selecting_finding_displays_details(self, window):
        result = {
            "score": 60,
            "level": "high",
            "findings": [
                {
                    "rule_id": "URL_001",
                    "title": "IP Address Hostname",
                    "severity": "high",
                    "description": "The URL uses an IP address.",
                    "evidence": "192.168.1.1",
                }
            ],
            "explanation": "A suspicious URL was detected.",
        }

        window.display_results(result)
        window.findings_table.selectRow(0)

        details = window.details.toPlainText()

        assert "URL_001" in details
        assert "IP Address Hostname" in details
        assert "HIGH" in details
        assert "192.168.1.1" in details

    def test_clear_results_resets_interface(self, window):
        window.url_input.setText("https://example.com")
        window.score_label.setText("60 / 100")
        window.level_label.setText("HIGH RISK")
        window.current_result = {"score": 60}
        window.export_button.setEnabled(True)

        window.clear_results()

        assert window.url_input.text() == ""
        assert window.score_label.text() == "-- / 100"
        assert window.level_label.text() == "AWAITING ANALYSIS"
        assert window.current_result is None
        assert window.findings_table.rowCount() == 0
        assert not window.export_button.isEnabled()
        assert window.explanation.text() == (
            "Enter a URL above to begin local analysis."
        )


class TestGuiAdditional:

    def test_zero_findings_display(self, window):
        result = {
            "score": 0,
            "level": "low",
            "findings": [],
            "explanation": "No suspicious characteristics detected.",
        }

        window.display_results(result)

        assert window.score_label.text() == "0 / 100"
        assert window.level_label.text() == "LOW RISK"
        assert window.findings_table.rowCount() == 0
        assert window.export_button.isEnabled()
        assert "does not guarantee" in window.details.toPlainText()

    def test_display_error_resets_assessment(self, window, monkeypatch):
        from PySide6.QtWidgets import QMessageBox

        monkeypatch.setattr(
            QMessageBox,
            "warning",
            lambda *args: QMessageBox.StandardButton.Ok,
        )

        window.current_result = {"score": 80}
        window.export_button.setEnabled(True)
        window.score_label.setText("80 / 100")

        window.display_error("Invalid URL.")

        assert window.current_result is None
        assert window.score_label.text() == "-- / 100"
        assert window.level_label.text() == "ANALYSIS FAILED"
        assert not window.export_button.isEnabled()
        assert window.explanation.text() == "Invalid URL."

    def test_export_json_creates_valid_file(
        self, window, monkeypatch, tmp_path
    ):
        import json
        from PySide6.QtWidgets import QFileDialog, QMessageBox

        result = {
            "original_url": "https://example.com",
            "normalized_url": "https://example.com",
            "score": 0,
            "level": "low",
            "findings": [],
            "explanation": "No findings detected.",
            "score_breakdown": {},
        }

        output_file = tmp_path / "assessment.json"
        window.current_result = result

        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            lambda *args: (str(output_file), "JSON Files (*.json)"),
        )

        monkeypatch.setattr(
            QMessageBox,
            "information",
            lambda *args: QMessageBox.StandardButton.Ok,
        )

        window.export_json()

        assert output_file.exists()

        with output_file.open("r", encoding="utf-8") as file:
            exported = json.load(file)

        assert exported == result

    def test_export_cancel_does_not_create_file(
        self, window, monkeypatch, tmp_path
    ):
        from PySide6.QtWidgets import QFileDialog

        window.current_result = {"score": 20}

        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            lambda *args: ("", ""),
        )

        window.export_json()

        assert list(tmp_path.iterdir()) == []

    def test_export_without_results_does_nothing(
        self, window, monkeypatch
    ):
        from PySide6.QtWidgets import QFileDialog

        def unexpected_dialog(*args):
            pytest.fail("Export dialog should not open without results.")

        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            unexpected_dialog,
        )

        window.current_result = None
        window.export_json()

    def test_export_handles_file_write_error(
        self, window, monkeypatch
    ):
        from pathlib import Path
        from PySide6.QtWidgets import QFileDialog, QMessageBox

        window.current_result = {"score": 20}

        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            lambda *args: ("assessment.json", "JSON Files (*.json)"),
        )

        errors = []

        monkeypatch.setattr(
            QMessageBox,
            "critical",
            lambda *args: errors.append(args),
        )

        def fail_open(self, *args, **kwargs):
            raise OSError("Permission denied")

        monkeypatch.setattr(Path, "open", fail_open)

        window.export_json()

        assert len(errors) == 1
        assert errors[0][1] == "Export Failed"
        assert "Permission denied" in errors[0][2]

    def test_clear_results_blocked_during_analysis(self, window):
        window.url_input.setText("https://example.com")
        window.analysis_thread = object()

        window.clear_results()

        assert window.url_input.text() == "https://example.com"

        window.analysis_thread = None

    def test_analysis_finished_restores_controls(self, window):
        window.analysis_thread = object()
        window.analysis_worker = object()

        window.analyze_button.setEnabled(False)
        window.clear_button.setEnabled(False)
        window.progress.show()

        window.analysis_finished()

        assert window.analyze_button.isEnabled()
        assert window.clear_button.isEnabled()
        assert not window.progress.isVisible()
        assert window.analysis_thread is None
        assert window.analysis_worker is None


class TestAnalysisWorkerIntegration:

    def test_successful_analysis_completes_and_cleans_up(self, window, app):
        from PySide6.QtCore import QElapsedTimer
        from PySide6.QtTest import QTest

        window.url_input.setText("https://example.com")
        window.start_analysis()

        assert window.analysis_thread is not None
        assert not window.analyze_button.isEnabled()
        assert not window.clear_button.isEnabled()
        assert window.progress.isVisible()

        timer = QElapsedTimer()
        timer.start()

        while window.analysis_thread is not None and timer.elapsed() < 5000:
            QTest.qWait(10)

        assert window.analysis_thread is None
        assert window.analysis_worker is None
        assert window.analyze_button.isEnabled()
        assert window.clear_button.isEnabled()
        assert not window.progress.isVisible()

        assert window.current_result is not None
        assert window.current_result["normalized_url"] == (
            "https://example.com"
        )
        assert window.current_result["score"] >= 0
        assert window.export_button.isEnabled()

    def test_invalid_url_completes_and_cleans_up(
        self, window, app, monkeypatch
    ):
        from PySide6.QtCore import QElapsedTimer
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QMessageBox

        monkeypatch.setattr(
            QMessageBox,
            "warning",
            lambda *args: QMessageBox.StandardButton.Ok,
        )

        window.url_input.setText("javascript:alert(1)")
        window.start_analysis()

        assert window.analysis_thread is not None

        timer = QElapsedTimer()
        timer.start()

        while window.analysis_thread is not None and timer.elapsed() < 5000:
            QTest.qWait(10)

        assert window.analysis_thread is None
        assert window.analysis_worker is None
        assert window.analyze_button.isEnabled()
        assert window.clear_button.isEnabled()
        assert not window.progress.isVisible()

        assert window.current_result is None
        assert window.level_label.text() == "ANALYSIS FAILED"
        assert not window.export_button.isEnabled()

    def test_unexpected_exception_completes_and_cleans_up(
        self, window, app, monkeypatch
    ):
        import phishlens.gui.main_window as gui_module
        from PySide6.QtCore import QElapsedTimer
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QMessageBox

        def raise_unexpected_error(url):
            raise RuntimeError("Forced test failure")

        monkeypatch.setattr(
            gui_module,
            "analyze_url",
            raise_unexpected_error,
        )

        monkeypatch.setattr(
            QMessageBox,
            "warning",
            lambda *args: QMessageBox.StandardButton.Ok,
        )

        window.url_input.setText("https://example.com")
        window.start_analysis()

        assert window.analysis_thread is not None

        timer = QElapsedTimer()
        timer.start()

        while window.analysis_thread is not None and timer.elapsed() < 5000:
            QTest.qWait(10)

        assert window.analysis_thread is None
        assert window.analysis_worker is None
        assert window.analyze_button.isEnabled()
        assert window.clear_button.isEnabled()
        assert not window.progress.isVisible()

        assert window.current_result is None
        assert "unexpected analysis error occurred" in (
            window.explanation.text()
        )
        assert "Forced test failure" in window.explanation.text()
        assert not window.export_button.isEnabled()
