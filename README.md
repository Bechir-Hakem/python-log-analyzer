
# Python Log Analyzer

A Python project that analyzes log files, tracks failed login attempts,
identifies suspicious activity, and generates a report.

## Features

- Reads and analyzes log files.
- Counts INFO, WARNING, and ERROR events.
- Tracks failed login attempts.
- Groups failed login attempts by username and IP address.
- Extracts and validates IPv4 addresses.
- Counts and ranks IP address activity.
- Identifies potentially suspicious users and IP addresses.
- Generates a structured text report.
- Handles missing files gracefully.
- Supports command-line arguments for selecting the log file.
- Includes automated unit tests.

## Requirements

- Python 3.10 or later
- Git

## How to Run

1. Clone the repository:

   ```bash
   git clone https://github.com/Bechir-Hakem/python-log-analyzer.git
   ```

2. Navigate to the project directory:

   ```bash
   cd python-log-analyzer
   ```

3. Run the analyzer with a log file:

   ```bash
   python main.py sample.log
   ```

4. The generated report will be saved in the `Reports` directory.

## Running Tests

Run the automated test suite with:

```bash
python -m unittest test_log_analyzer -v
```

The tests cover IP validation, log analysis, file reading, and report generation.
