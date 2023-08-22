from ..fuzzable import Fuzzable


class Simple(Fuzzable):
    """
    Simple 原语根据一个由单字节值组成的列表来进行模糊测试。
    
    .. 
     Simple bytes value with manually specified fuzz values only.

    :type name: str, optional
    :param name: Simple 原语的名称，默认为 None
    :type default_value: Raw, optional
    :param default_value: 原始静态数据
    :type fuzz_values: list, optional
    :param fuzz_values: 由 fuzz 值组成的列表，默认为 None。如果为 None，那么 Simple 原语就等价于 Static 原语了。
    :type  fuzzable: bool, optional
    :param fuzzable: 启用/禁用对 Simple 原语的模糊测试，默认为 True
    """

    def __init__(self, name=None, default_value=None, fuzz_values=None, *args, **kwargs):
        super(Simple, self).__init__(name=name, default_value=default_value, fuzz_values=fuzz_values, *args, **kwargs)
