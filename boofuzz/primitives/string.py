import itertools
import math
import random

from ..fuzzable import Fuzzable


class String(Fuzzable):
    """String 原语通过变异事先定义好的字符串库从而进行模糊测试。

    类变量 'fuzz_library' 是一个包含着 fuzz 值的列表，所有实例都可共享该变量.

    :type name: str, 可选
    :param name: 名称，用于后续引用。若未提供名称，那么默认为 None。
    :type default_value: str，可选
    :param default_value: 当元素不进行模糊测试时所用的值，通常情况下应是一个有效值。
    :type size: int, 可选
    :param size: 该字段的静态长度，若为 None 则表示该字段是动态的。默认为 None。
    :type padding: chr, 可选
    :param padding: 用于填充静态字段长度的值，默认为 "\\x00"。
    :type encoding: str, 可选
    :param encoding: 字符串编码类型，比如微软的 Unicode utf_16_le。
    :param max_len: 变异字符串的最大长度，默认为 None。
    :type fuzzable: bool, 可选
    :param fuzzable: 启用/禁用对该原语的模糊测试，默认为 true。
    """

    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    # Has to be sorted to avoid duplicates
    _fuzz_library = [
        "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
        "",  # strings ripped from spike (and some others I added)
        "$(reboot)",
        "$;reboot",
        "%00",
        "%00/",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "%0a reboot %0a",
        "%0Areboot",
        "%0Areboot%0A",
        "%0DCMD=$'reboot';$CMD",
        '%0DCMD=$"reboot";$CMD',
        "%0Dreboot",
        "%0Dreboot%0D",
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff" * 20,
        "%n" * 100,  # format strings.
        "%n" * 500,
        "%s" * 100,
        "%s" * 500,
        "%u0000",
        "& reboot &",
        "& reboot",
        "&&CMD=$'reboot';$CMD",
        '&&CMD=$"reboot";$CMD',
        "&&reboot",
        "&&reboot&&",
        "&CMD=$'reboot';$CMD",
        '&CMD=$"reboot";$CMD',
        "&reboot",
        "&reboot&",
        "'reboot'",
        "..:..:..:..:..:..:..:..:..:..:..:..:..:",
        "/%00/",
        "/." * 5000,
        "/.../" + "B" * 5000 + "\x00\x00",
        "/.../.../.../.../.../.../.../.../.../.../",
        "/../../../../../../../../../../../../boot.ini",
        "/../../../../../../../../../../../../etc/passwd",
        "/.:/" + "A" * 5000 + "\x00\x00",
        "/\\" * 5000,
        "/index.html|reboot|",
        "; reboot",
        ";CMD=$'reboot';$CMD",
        ';CMD=$"reboot";$CMD',
        ";id",
        ";notepad;",
        ";reboot",
        ";reboot/n",
        ";reboot;",
        ";reboot|",
        ";system('reboot')",
        ";touch /tmp/SULLEY;",
        ";|reboot|",
        '<!--#exec cmd="reboot"-->',
        "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
        "<reboot",
        "<reboot%0A",
        "<reboot%0D",
        "<reboot;",
        '"%n"' * 500,
        '"%s"' * 500,
        "\\\\*",
        "\\\\?\\",
        "\nnotepad\n",
        "\nreboot\n",
        "\r\n" * 100,  # miscellaneous.
        "\x01\x02\x03\x04",
        "\xde\xad\xbe\xef" * 10,
        "\xde\xad\xbe\xef" * 100,
        "\xde\xad\xbe\xef" * 1000,
        "\xde\xad\xbe\xef" * 10000,
        "\xde\xad\xbe\xef",  # some binary strings.
        "^CMD=$'reboot';$CMD",
        '^CMD=$"reboot";$CMD',
        "^reboot",
        "`reboot`",
        "a);reboot",
        "a);reboot;",
        "a);reboot|",
        "a)|reboot",
        "a)|reboot;",  # fuzzdb command injection
        "a;reboot",
        "a;reboot;",
        "a;reboot|",
        "a|reboot",
        "CMD=$'reboot';$CMD",
        'CMD=$"reboot";$CMD',
        "FAIL||CMD=$'reboot';$CMD",
        'FAIL||CMD=$"reboot";$CMD',
        "FAIL||reboot",
        "id",
        "id;",
        "id|",
        "reboot",
        "reboot;",
        "reboot|",
        "| reboot",
        "|CMD=$'reboot';$CMD",
        '|CMD=$"reboot";$CMD',
        "|nid",
        "|notepad",
        "|reboot",
        "|reboot;",
        "|reboot|",
        "|touch /tmp/SULLEY",  # command injection.
        "||reboot;",
        "||reboot|",
    ]

    long_string_seeds = [
        "C",
        "1",
        "<",
        ">",
        "'",
        '"',
        "/",
        "\\",
        "?",
        "=",
        "a=",
        "&",
        ".",
        ",",
        "(",
        ")",
        "]",
        "[",
        "%",
        "*",
        "-",
        "+",
        "{",
        "}",
        "\x14",
        "\x00",
        "\xFE",  # expands to 4 characters under utf1
        "\xFF",  # expands to 4 characters under utf1
    ]

    _long_string_lengths = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]
    _long_string_deltas = [-2, -1, 0, 1, 2]
    _extra_long_string_lengths = [99999, 100000, 500000, 1000000]

    _variable_mutation_multipliers = [2, 10, 100]

    def __init__(
        self, name=None, default_value="", size=None, padding=b"\x00", encoding="utf-8", max_len=None, *args, **kwargs
    ):
        super(String, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.size = size
        self.max_len = max_len
        if self.size is not None:
            self.max_len = self.size
        self.encoding = encoding
        self.padding = padding
        if isinstance(padding, str):
            self.padding = self.padding.encode(self.encoding)
        self._static_num_mutations = None
        self.random_indices = {}

        local_random = random.Random(0)  # We want constant random numbers to generate reproducible test cases
        previous_length = 0
        # For every length, add a random number of random indices to the random_indices dict. Prevent duplicates by
        # adding only indices in between previous_length and current length.
        for length in self._long_string_lengths:
            self.random_indices[length] = local_random.sample(
                range(previous_length, length), local_random.randint(1, self._long_string_lengths[0]) # 生成一个范围在 preL 和 L
                # 之间的长度为 randint 的列表
            )
            previous_length = length

    def _yield_long_strings(self, sequences):
        """
        Given a sequence, yield a number of selectively chosen strings lengths of the given sequence.

        @type  sequences: list(str)
        @param sequences: Sequence to repeat for creation of fuzz strings.
        """
        for sequence in sequences:
            for size in [
                length + delta
                for length, delta in itertools.product(self._long_string_lengths, self._long_string_deltas)
            ]:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    yield data[:size]
                else:
                    break

            for size in self._extra_long_string_lengths:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    yield data[:size]
                else:
                    break

            if self.max_len is not None:
                data = sequence * math.ceil(self.max_len / len(sequence))
                yield data

        for size in self._long_string_lengths:
            if self.max_len is None or size <= self.max_len:
                s = "D" * size
                for loc in self.random_indices[size]:
                    yield s[:loc] + "\x00" + s[loc + 1 :]  # Replace character at loc with terminator
            else:
                break

    def _yield_variable_mutations(self, default_value):
        for length in self._variable_mutation_multipliers:
            value = default_value * length
            if value not in self._fuzz_library:
                yield value
                if self.max_len is not None and len(value) >= self.max_len:
                    break

    def _adjust_mutation_for_size(self, fuzz_value):
        if self.max_len is not None and self.max_len < len(fuzz_value):
            return fuzz_value[: self.max_len]
        else:
            return fuzz_value

    def mutations(self, default_value):
        """
        通过逐步遍历 fuzz 库对当前原语进行变异。
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        Args:
            default_value (str): 元素的默认值（Default value of element.）

        Yields:
            str: 变异后的字符串（Mutations）
        """
        last_val = None

        for val in itertools.chain(
            self._fuzz_library,
            self._yield_variable_mutations(default_value),
            self._yield_long_strings(self.long_string_seeds),
        ):
            current_val = self._adjust_mutation_for_size(val)
            if last_val == current_val:
                continue
            last_val = current_val
            yield current_val

        # TODO: Add easy and sane string injection from external file/s

    def encode(self, value, mutation_context=None):
        value = value.encode(self.encoding, "replace")
        # pad undersized library items.
        if self.size is not None and len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return value

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """
        variable_num_mutations = sum(1 for _ in self._yield_variable_mutations(default_value=default_value))
        if self._static_num_mutations is None:
            #  Counting the number of mutations with default value "" results in 0 variable_num_mutations 3 * "" = ""
            self._static_num_mutations = sum(1 for _ in self.mutations(default_value=""))
        return self._static_num_mutations + variable_num_mutations
