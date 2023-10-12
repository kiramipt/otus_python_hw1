#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import copy
import datetime
import gzip
import json
import logging
import os
import re
from collections import namedtuple
from statistics import median
from string import Template
from typing import Callable, Dict, Iterator, Optional, Tuple

DEFAULT_CONFIG = {
    "REPORT_SIZE": 10,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./logs",
    "LOG_FILE": None,
    "ERRORS_LIMIT": 0.64,
}

DEFAULT_CONFIG_PATH = "./config.json"

FILE_NAME_REGEXP = re.compile(r"^nginx-access-ui\.log-(?P<date>\d{8})(\.gz)?$")

NGINX_LOG_FORMAT_REGEXP = re.compile(
    r"(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<remote_user>.*?)\s+"
    r"(?P<http_x_real_ip>.*?)\s+\[(?P<time_local>.*?)\]\s+\"(?P<request_method>.*?)\s+"
    r"(?P<path>.*?)(?P<request_version>\s+HTTP/.*)?\"\s+(?P<status>.*?)\s+"
    r"(?P<body_bytes_sent>.*?)\s+\"(?P<http_referer>.*?)\"\s+\"(?P<user_agent>.*?)\"\s+"
    r"\"(?P<http_x_forwarded_for>.*?)\"\s+\"(?P<http_X_REQUEST_ID>.*?)\"\s+"
    r"\"(?P<http_X_RB_USER>.*)\"\s+(?P<request_time>\d+\.?\d*)"
)

CUR_DIR = os.path.dirname(os.path.abspath(__file__))


class ErrorsLimitExceedError(Exception):
    pass


def setup_logging(log_file: str) -> None:
    """
    Setup logging with configs.

    :param log_file: log file name
    """
    logging.basicConfig(
        format="[%(asctime)s] %(levelname).1s %(message)s",
        filename=log_file,
        level=logging.INFO,
        datefmt="%Y.%m.%d %H:%M:%S",
    )


def find_last_log_file(dir_path: str) -> Optional[namedtuple]:
    """
    Find last log file in directory.

    :param dir_path: dir path in which we search log files
    :return: return last_log_info, namedtuple with file_path and date of last log
    """

    if not os.path.isdir(dir_path):
        logging.info("Log directory was not founded")
        return

    last_log_info = None

    # namedtuple for quick access for log info
    LogInfo = namedtuple(
        "LogInfo",
        [
            "file_path",
            "date",
        ],
    )

    # try to find last log file
    for file_name in os.listdir(dir_path):
        match = re.match(FILE_NAME_REGEXP, file_name)

        if match:
            log_date = match.groupdict()["date"]
            try:
                log_date = datetime.datetime.strptime(log_date, "%Y%m%d").date()
            except ValueError:
                continue

            if not last_log_info or log_date > last_log_info.date:
                last_log_info = LogInfo(os.path.join(dir_path, file_name), log_date)

    return last_log_info


def process_line(line: str) -> Optional[Tuple[str, float]]:
    """
    Process one line of log file.

    :param line: log line
    :return: tuple with route and request_time if line match to regexp
    """

    result = NGINX_LOG_FORMAT_REGEXP.match(line)
    if result:
        url, request_time = result.group("path"), float(result.group("request_time"))
        return url, request_time


def parse_log(file_path: str) -> Iterator[Optional[Tuple[str, float]]]:
    """
    Return one line of log at time.

    :param file_path: path to file with logs
    """

    file_open = gzip.open if file_path.endswith(".gz") else open
    with file_open(file_path, "rt") as f:
        for line in f:
            yield process_line(line)


def calculate_statistics(
    file_path: str, log_parser: Callable, errors_limit: float = None
) -> Dict:
    """
    Calculate statistics using data from file.

    :param file_path: path to file with logs
    :param log_parser: logs file parser
    :param errors_limit: error percent that critical to statistics
    :return: dictionary with statistics by each unique url
    """

    total = processed = processed_request_time = 0
    statistics = {}

    for parsed_line in log_parser(file_path):
        total += 1
        if parsed_line:
            processed += 1
            url, request_time = parsed_line
            statistics.setdefault(url, []).append(request_time)
            processed_request_time += request_time

    if errors_limit is not None and total > 0:
        cur_errors_limit = (total - processed) / total
        if cur_errors_limit:
            raise ErrorsLimitExceedError(
                f"Errors limit = {errors_limit} was exceed, current errors limit={cur_errors_limit}"
            )

    all_count = processed
    all_time_sum = processed_request_time

    # calculate enriched_ statistics for html report
    enriched_statistics = {}
    for url, data in statistics.items():
        count = len(data)
        count_perc = count / all_count
        time_sum = sum(data)
        time_perc = time_sum / all_time_sum
        time_avg = time_sum / count
        time_max = max(data)
        time_med = median(data)

        enriched_statistics[url] = {
            "url": url,
            "count": count,
            "count_perc": round(count_perc * 100, 3),
            "time_sum": round(time_sum, 3),
            "time_perc": round(time_perc * 100, 3),
            "time_avg": round(time_avg, 3),
            "time_max": round(time_max, 3),
            "time_med": round(time_med, 3),
        }

    return enriched_statistics


def render_template(
    template_file_path: str, report_file_path: str, statistics: list[dict]
) -> None:
    """
    Render statistics in html report using template and write it into report file

    :param template_file_path: path to template
    :param report_file_path: path to created report
    :param statistics: list of dict with statistics
    """

    # open report template file and replace $table_json to our data
    try:
        with open(template_file_path) as f:
            s = Template(f.read())
            s = s.safe_substitute(table_json=json.dumps(statistics))
    except FileNotFoundError:
        logging.error(f"Template file {template_file_path} was not founded")
        return

    # write rendered report to report file
    with open(report_file_path, "w") as f:
        f.write(s)


def main(config: dict) -> None:
    """
    Start all calculations.

    :param config: dict with configs
    """

    last_log_info = find_last_log_file(config["LOG_DIR"])
    if not last_log_info:
        logging.info("Log file was not founded")
        return

    report_file_name = f"report-{last_log_info.date.strftime('%Y.%m.%d')}.html"

    if not os.path.isdir(config["REPORT_DIR"]):
        os.makedirs(config["REPORT_DIR"])
        logging.info(
            f"Create report directory {config['REPORT_DIR']} because it doesn't exist."
        )

    report_file_path = os.path.join(config["REPORT_DIR"], report_file_name)
    template_file_path = os.path.join(config["REPORT_DIR"], "report.html")

    if not os.path.isfile(template_file_path):
        logging.error(f"Template file {template_file_path} doesn't exist")
        return

    if os.path.isfile(report_file_path):
        logging.info("Current report is up-to-date")
        return

    statistics = calculate_statistics(
        last_log_info.file_path, parse_log, config["ERRORS_LIMIT"]
    )
    top_statistics = sorted(
        statistics.values(), key=lambda x: x["time_sum"], reverse=True
    )[: config["REPORT_SIZE"]]

    render_template(template_file_path, report_file_path, top_statistics)


if __name__ == "__main__":
    # create parser for config file path
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", help="path to config file", default=DEFAULT_CONFIG_PATH
    )
    args = parser.parse_args()
    config_filepath = args.config
    config = copy.deepcopy(DEFAULT_CONFIG)

    # read external config file
    try:
        with open(config_filepath) as f:
            external_config = json.load(f)
        # update default configs with external values
        config.update(external_config)
    except FileNotFoundError:
        logging.error(f"Config file {config_filepath} was not founded")

    # setup logging configs
    setup_logging(config["LOG_FILE"])

    # launch log analyzer
    try:
        main(config)
    except:
        logging.exception("Exception in main function")
