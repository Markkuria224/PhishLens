# PhishLens Architecture

## 1. Overview

PhishLens is a Windows desktop application that performs local heuristic analysis of URLs to identify potentially suspicious characteristics.

The application normalizes submitted URLs, evaluates them against a set of detection rules, calculates a risk score, and presents explainable findings through a graphical interface.

PhishLens does not visit submitted URLs or make network requests during analysis.

## 2. Technology Stack

- **Language:** Python 3.12+
- **GUI framework:** PySide6
- **URL parsing:** Python standard library (`urllib.parse`)
- **Testing:** pytest
- **Packaging:** setuptools
- **Output format:** JSON

## 3. Project Structure

```text
PhishLens/
|
+-- src/
|   +-- phishlens/
|       +-- main.py
|       +-- core/
|       |   +-- normalizer.py
|       |   +-- rules.py
|       |   +-- analyzer.py
|       |   +-- scoring.py
|       +-- gui/
|           +-- main_window.py
|
+-- tests/
+-- docs/
+-- README.md
+-- pyproject.toml
+-- .gitignore
```

## 4. Component Responsibilities

### URL Normalizer
File: `core/normalizer.py`

Validates and normalizes submitted URLs. Handles supported schemes, hostname validation, IDNA conversion, embedded credentials, and malformed ports.

### Detection Rules
File: `core/rules.py`

Defines the Finding data structure, rule identifiers, severity levels, weights, and shared heuristic configuration.

### Analysis Engine
File: `core/analyzer.py`

Evaluates normalized URLs against nine active heuristic rules, identifying suspicious characteristics such as IP-based hostnames, HTTP usage, excessive subdomains, and suspicious keywords.

### Risk Scoring
File: `core/scoring.py`

Calculates each finding's contribution by multiplying severity points (low: 10, medium: 20, high: 30) by its weight. Duplicate rule IDs retain the highest contribution. Contributions are summed, rounded, and capped at 100.

| Score | Category |
|---|---|
| 0-24 | Low |
| 25-49 | Moderate |
| 50-74 | High |
| 75-100 | Critical |

### Graphical Interface
File: `gui/main_window.py`

Provides URL input, analysis controls, progress indication, findings, risk assessment, and JSON export.

## 5. Analysis Lifecycle

1. User submits a URL.
2. The GUI starts background processing.
3. The normalizer validates the URL.
4. The analyzer evaluates active heuristic rules.
5. The scoring component calculates the risk level.
6. Results are returned to the GUI.
7. The user can inspect or export the assessment.

## 6. Background Processing

PhishLens uses Qt threading functionality to keep the graphical interface responsive during analysis.

The AnalysisWorker performs normalization, heuristic analysis, and scoring outside the GUI thread. It communicates results and errors through Qt signals. Its completion signal initiates thread shutdown and worker cleanup; the finished thread is then cleaned up.

## 7. Assessment and Export

Results include the original URL, normalized URL, timestamp, risk score, risk category, findings, explanation, and score breakdown.

Assessments can be exported in JSON format.

## 8. Security and Privacy

PhishLens performs local-only analysis.

It does not:
- Visit submitted URLs.
- Perform DNS resolution.
- Send URLs to external services.
- Execute remote JavaScript.
- Download remote content.
- Use threat-intelligence APIs.
- Transmit analysis telemetry.

## 9. Limitations

PhishLens uses heuristic detection. A low-risk result does not guarantee safety, and a high-risk result does not prove maliciousness.

The application is an assessment aid, not a replacement for professional security analysis or antivirus protection.

## 10. Design Principles

- Local-first processing.
- Separation of application components.
- Explainable detection findings.
- Responsive graphical interface.
- Controlled URL handling.
- Automated testability.
