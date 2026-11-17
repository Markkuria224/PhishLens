"""Application entry point for PhishLens."""

import sys

from PySide6.QtWidgets import QApplication

from phishlens.gui.main_window import MainWindow


def main() -> None:
    """Launch the PhishLens desktop application."""
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
