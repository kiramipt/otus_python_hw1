import bz2
import gzip
import json
import logging
import os
import shutil


import unittest
from typing import Optional

import log_analyzer as log_analyzer

TEST_LOG_1 = """0.0.0.0 -  - [] "GET /api1 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" 1
0.0.0.0 -  - [] "GET /api1 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" 1.4
0.0.0.0 -  - [] "GET /api2 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" 2
"""

TEST_LOG_2 = """0.0.0.0 -  - [] "GET /api1 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" 1
0.0.0.0 -  - [] "GET /api1 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" 1.4
0.0.0.0 -  - [] "GET /api2 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" 2
0.0.0.0 -  - [] "GET /api2 HTTP/1.1" 200 927 "-" "-" "-" "-" "-" "-"
"""

TEST_ANSWER_1 = [
    {
        "url": "/api1",
        "count": 2,
        "count_perc": 66.667,
        "time_sum": 2.4,
        "time_perc": 54.545,
        "time_avg": 1.2,
        "time_max": 1.4,
        "time_med": 1.2,
    },
    {
        "url": "/api2",
        "count": 1,
        "count_perc": 33.333,
        "time_sum": 2.0,
        "time_perc": 45.455,
        "time_avg": 2.0,
        "time_max": 2.0,
        "time_med": 2.0,
    },
]


def create_file_and_write_several_lines(
    path: str, lines: str, compress: Optional[str] = None
) -> None:
    """
    Create file and write in it data

    :param path: path to file
    :param lines: data which we write in it
    :param compress: file extension
    :return: None
    """

    openers_map = {"gz": gzip.GzipFile, "bz2": bz2.BZ2File, None: open}
    opener = openers_map.get(compress, open)
    compressed_path = "%s.%s" % (path, compress) if compress else path
    with opener(compressed_path, "wb") as fp:
        for line in lines:
            fp.write(line.encode("ascii"))


def set_up_test_files() -> list:
    """
    Create all files that we need for tests

    :return: test cases directories
    """

    # create environments parent folder
    parent_dir = "./test_environments"
    os.makedirs(parent_dir, exist_ok=True)

    # create environments folders
    case_n = 4
    cases_dict = {}
    env_dir_template = os.path.join(parent_dir, "environment_{0}")
    for i in range(1, case_n + 1):
        os.makedirs(env_dir_template.format(i), exist_ok=True)

    for i in range(1, case_n + 1):
        log_dir = os.path.join(env_dir_template.format(i), "log")
        report_dir = os.path.join(env_dir_template.format(i), "report")
        cases_dict["case_{0}".format(i)] = {
            "REPORT_DIR": report_dir,
            "LOG_DIR": log_dir,
            "LOG_FILE": os.path.join(env_dir_template.format(i), "log_file.log"),
            "ERRORS_LIMIT": 0.1,
            "REPORT_SIZE": 10,
        }

        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(report_dir, exist_ok=True)

        create_file_and_write_several_lines(
            os.path.join(report_dir, "report.html"), "var table = $table_json;"
        )

    # first case:
    create_file_and_write_several_lines(
        path=os.path.join(
            cases_dict["case_1"]["LOG_DIR"], "nginx-access-ui.log-20170628"
        ),
        lines=TEST_LOG_1,
        compress=None,
    )
    create_file_and_write_several_lines(
        path=os.path.join(
            cases_dict["case_1"]["LOG_DIR"], "nginx-access-ui.log-20170629"
        ),
        lines=TEST_LOG_1,
        compress="gz",
    )
    create_file_and_write_several_lines(
        path=os.path.join(
            cases_dict["case_1"]["LOG_DIR"], "nginx-access-ui.log-20170630"
        ),
        lines=TEST_LOG_1,
        compress="bz2",
    )

    # second case:
    create_file_and_write_several_lines(
        path=os.path.join(
            cases_dict["case_2"]["LOG_DIR"], "nginx-access-ui.log-20170628"
        ),
        lines=TEST_LOG_1,
        compress="bz2",
    )

    # third case:
    create_file_and_write_several_lines(
        path=os.path.join(
            cases_dict["case_3"]["LOG_DIR"], "nginx-access-ui.log-20170628"
        ),
        lines=TEST_LOG_1,
        compress=None,
    )
    create_file_and_write_several_lines(
        path=os.path.join(cases_dict["case_3"]["REPORT_DIR"], "report-2017.06.28.html"),
        lines="",
        compress=None,
    )

    # fourth case:
    create_file_and_write_several_lines(
        path=os.path.join(
            cases_dict["case_4"]["LOG_DIR"], "nginx-access-ui.log-20170628"
        ),
        lines=TEST_LOG_2,
        compress=None,
    )

    return [(k, v) for k, v in cases_dict.items()]


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.cases = set_up_test_files()

    def test_case_1_log_file_created(self):
        case_name, config = self.cases[0]

        # close previous log handler
        log = logging.getLogger()
        for hdlr in log.handlers:
            hdlr.close()
            log.removeHandler(hdlr)

        log_analyzer.setup_logging(config["LOG_FILE"])
        log_analyzer.main(config)

        # check that log file created
        self.assertTrue(
            os.path.isfile(config["LOG_FILE"]),
            msg="Log file not been created in {0}".format(config["LOG_FILE"]),
        )

    def test_case_1_report_file_created_with_correct_date(self):
        case_name, config = self.cases[0]

        # close previous log handler
        log = logging.getLogger()
        for hdlr in log.handlers:
            hdlr.close()
            log.removeHandler(hdlr)

        log_analyzer.setup_logging(config["LOG_FILE"])
        log_analyzer.main(config)

        # check that report file created
        self.assertTrue(
            os.path.isfile(
                os.path.join(config["REPORT_DIR"], "report-2017.06.29.html")
            ),
            msg="Report file not been created in {0}".format(config["REPORT_DIR"]),
        )

    def test_case_1_report_file_contain_correct_data(self):
        case_name, config = self.cases[0]

        # close previous log handler
        log = logging.getLogger()
        for hdlr in log.handlers:
            hdlr.close()
            log.removeHandler(hdlr)

        log_analyzer.setup_logging(config["LOG_FILE"])
        log_analyzer.main(config)

        # read result from report file
        report_file = os.path.join(config["REPORT_DIR"], "report-2017.06.29.html")
        with open(report_file) as f:
            data = f.read()
        data = json.loads(data.split("= ")[1][:-1])

        # check that report result is correct
        self.assertCountEqual(
            data, TEST_ANSWER_1, msg="Report file contain not correct data"
        )

    def test_case_2_rise_not_founded_log_files(self):
        case_name, config = self.cases[1]

        # close previous log handler
        log = logging.getLogger()
        for hdlr in log.handlers:
            hdlr.close()
            log.removeHandler(hdlr)

        log_analyzer.setup_logging(config["LOG_FILE"])
        log_analyzer.main(config)

        with open(config["LOG_FILE"]) as f:
            data = f.read()

        # check that log file has info msg
        self.assertTrue(
            data.find("Log file was not founded") != -1,
            msg="Not rises info msg: 'Log file was not founded'",
        )

    def test_case_3_rise_current_report_is_uptodate(self):
        case_name, config = self.cases[2]

        # close previous log handler
        log = logging.getLogger()
        for hdlr in log.handlers:
            hdlr.close()
            log.removeHandler(hdlr)

        log_analyzer.setup_logging(config["LOG_FILE"])
        log_analyzer.main(config)

        with open(config["LOG_FILE"]) as f:
            data = f.read()

        # check that log file has info msg
        self.assertTrue(
            data.find("Current report is up-to-date") != -1,
            msg="Not rises info msg: 'Current report is up-to-date'",
        )

    def test_case_4_rise_errors_limit_exceed(self):
        case_name, config = self.cases[3]

        # close previous log handler
        log = logging.getLogger()
        for hdlr in log.handlers:
            hdlr.close()
            log.removeHandler(hdlr)

        self.assertRaises(Exception, log_analyzer.main, config)

    def tearDown(self):
        shutil.rmtree("./test_environments")


if __name__ == "__main__":
    unittest.main()
