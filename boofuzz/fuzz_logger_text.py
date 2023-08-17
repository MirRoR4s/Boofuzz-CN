import sys

from colorama import init

from . import helpers, ifuzz_logger_backend

init()

DEFAULT_HEX_TO_STR = helpers.hex_to_hexstr


class FuzzLoggerText(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    该类会将 FuzzLogger 数据格式化成文本形式并输出到标准输出或是文件中。
    如果想要既输出到标准输出又输出到文件中，可以使用两个 FUzzLoggerTexts。
    """

    INDENT_SIZE = 2

    def __init__(self, file_handle=sys.stdout, bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        :type file_handle: io.BinaryIO
        :param file_handle: 一个用于日志记录的文件句柄，默认值为`sys.stdout`，也就是标准输出流

        :type bytes_to_str: function
        :param bytes_to_str: 用于将发送/接收的字节数据转换为字符串以进行日志记录，默认值为 DEFAULT_HEX_TO_STR
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str

    def open_test_step(self, description):
        self._print_log_msg(msg=description, msg_type="step")

    def log_check(self, description):
        self._print_log_msg(msg=description, msg_type="check")

    def log_error(self, description):
        self._print_log_msg(msg=description, msg_type="error")

    def log_recv(self, data):
        self._print_log_msg(data=data, msg_type="receive")

    def log_send(self, data):
        self._print_log_msg(data=data, msg_type="send")

    def log_info(self, description):
        self._print_log_msg(msg=description, msg_type="info")

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._print_log_msg(msg=test_case_id, msg_type="test_case")

    def log_fail(self, description=""):
        self._print_log_msg(msg=description, msg_type="fail")

    def log_pass(self, description=""):
        self._print_log_msg(msg=description, msg_type="pass")

    def close_test_case(self):
        pass

    def close_test(self):
        pass

    def _print_log_msg(self, msg_type, msg=None, data=None):
        print(
            helpers.format_log_msg(msg_type=msg_type, description=msg, data=data, indent_size=self.INDENT_SIZE),
            file=self._file_handle,
        )
