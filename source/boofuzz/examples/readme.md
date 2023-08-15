# 样例分析

## 前言

从官方给出的样例中学习 boofuzz 的基本使用。

```python
#!/usr/bin/env python
"""Demo of a very simple protocol definition using the Simple primitive.
一个使用 Simple 原语的简单案例
"""

from boofuzz import *
import boofuzz
import click


@click.command() #  将函数注册为命令
@click.pass_context
def simple(ctx):
    cli_context = ctx.obj
    session = cli_context.session
    session._receive_data_after_each_request = False #  每个请求之后不接收数据

    message1 = Request(
        "message1",
        children=(
            Simple(name="first_byte", default_value=b"\x01", fuzz_values=[b"A", b"B", b"C"]),
            Simple(name="second_byte", default_value=b"\x02", fuzz_values=[b"1", b"2", b"3"]),
            Simple(name="third_byte", default_value=b"\x03", fuzz_values=[b"X", b"Y", b"Z"]),
        ),
    )

    message2 = Request(
        "message2",
        children=(
            Simple(name="first_byte", default_value=b"\x01", fuzz_values=[b"A", b"B", b"C"]),
            Simple(name="second_byte", default_value=b"\x02", fuzz_values=[b"1", b"2", b"3"]),
        ),
    )
    """
    将请求对象连接起来形成流程
    """
    session.connect(message1)
    session.connect(message1, message2)


if __name__ == "__main__":
    boofuzz.main_helper(click_command=simple)
```

