from .base_primitive import BasePrimitive
from .. import helpers


class Delim(BasePrimitive):
    r"""表示一个分隔符，比如空格,\r,\n, ,=,>,< 等等。注意变异包括重复、替换、缺少。

    :param name: 名称, 用于后续引用。默认为 None。
    :type name: str, optional
    :param default_value: 当元素不进行模糊测试时所用的值，通常情况下应是一个合法的协议字段值。
    :type default_value: char, optional
    :param fuzzable: 启用/禁用对该原语的模糊测试，默认为 true。
    :type fuzzable: bool, optional
    """

    def __init__(self, name=None, default_value=" ", *args, **kwargs):
        super(Delim, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self._fuzz_library.append(self._default_value * 2)
        self._fuzz_library.append(self._default_value * 5)
        self._fuzz_library.append(self._default_value * 10)
        self._fuzz_library.append(self._default_value * 25)
        self._fuzz_library.append(self._default_value * 100)
        self._fuzz_library.append(self._default_value * 500)
        self._fuzz_library.append(self._default_value * 1000)

        self._fuzz_library.append("")
        if self._default_value == " ":
            self._fuzz_library.append("\t")
            self._fuzz_library.append("\t" * 2)
            self._fuzz_library.append("\t" * 100)

        self._fuzz_library.append(" ")
        self._fuzz_library.append("\t")
        self._fuzz_library.append("\t " * 100)
        self._fuzz_library.append("\t\r\n" * 100)
        self._fuzz_library.append("!")
        self._fuzz_library.append("@")
        self._fuzz_library.append("#")
        self._fuzz_library.append("$")
        self._fuzz_library.append("%")
        self._fuzz_library.append("^")
        self._fuzz_library.append("&")
        self._fuzz_library.append("*")
        self._fuzz_library.append("(")
        self._fuzz_library.append(")")
        self._fuzz_library.append("-")
        self._fuzz_library.append("_")
        self._fuzz_library.append("+")
        self._fuzz_library.append("=")
        self._fuzz_library.append(":")
        self._fuzz_library.append(": " * 100)
        self._fuzz_library.append(":7" * 100)
        self._fuzz_library.append(";")
        self._fuzz_library.append("'")
        self._fuzz_library.append('"')
        self._fuzz_library.append("/")
        self._fuzz_library.append("\\")
        self._fuzz_library.append("?")
        self._fuzz_library.append("<")
        self._fuzz_library.append(">")
        self._fuzz_library.append(".")
        self._fuzz_library.append(",")
        self._fuzz_library.append("\r")
        self._fuzz_library.append("\n")
        self._fuzz_library.append("\r\n" * 64)
        self._fuzz_library.append("\r\n" * 128)
        self._fuzz_library.append("\r\n" * 512)

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)
