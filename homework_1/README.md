# Getting Started
To run script use: ```python log_analyzer.py```

To pass your params through json file use: ```python log_analyzer.py --config config.json```

Example of file with config params:
* **LOG_DIR**: path to directory with log files (default="./log")
* **LOG_FILE**: path to script logging file (default=None)
* **REPORT_DIR**: path to directory with report files (default="./reports")
* **REPORT_SIZE**: size of report, render statistics only for top n urls (default=10)
* **ERRORS_LIMIT**: percentage of errors which we can allow when parsing log files (default=0.64)

To run unittest use: ```python test_log_anayzer.py```