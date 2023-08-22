from .. import helpers
from ..fuzzable import Fuzzable


class Static(Fuzzable):
    """
    
    ..
     Static primitives are fixed and not mutated while fuzzing.

    :type name: str, optional
    :param name: Static 原语的名称，默认为 None
    :type default_value: Raw, optional
    :param default_value: 原始的静态数据
    """

    def __init__(self, name=None, default_value=None, *args, **kwargs):
        super(Static, self).__init__(name=name, default_value=default_value, fuzzable=False, *args, **kwargs)

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)
