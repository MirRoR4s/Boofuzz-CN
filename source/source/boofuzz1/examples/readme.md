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

### ftp_simple



```
#!/usr/bin/env python3
"""Demo FTP fuzzer as a standalone script."""

from boofuzz import *


def main():
    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 21)))

    define_proto(session=session)

    session.fuzz()


def define_proto(session):
    # disable Black formatting to keep custom indentation
    # fmt: off
    user = Request("user", children=(
        String(name="key", default_value="USER"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="anonymous"),
        Static(name="end", default_value="\r\n"),
    ))

    passw = Request("pass", children=(
        String(name="key", default_value="PASS"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="james"),
        Static(name="end", default_value="\r\n"),
    ))

    stor = Request("stor", children=(
        String(name="key", default_value="STOR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    retr = Request("retr", children=(
        String(name="key", default_value="RETR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))
    # fmt: on

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)


def define_proto_static(session):
    """Same protocol, using the static definition style."""
    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))


if __name__ == "__main__":
    main()
```



### tftp_simple

这是一个针对 tftp 协议的模糊测试代码。

```python
#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

from boofuzz import *


def main():
    port = 69
    host = "127.0.0.1"

    session = Session(
        target=Target(
            connection=UDPSocketConnection(host, port),
        ),
    )

    s_initialize("RRQ")
    s_static("\x00\x01")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_string("netascii", name="Mode")
    s_static("\x00")

    s_initialize("WRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_string("netascii", name="Mode")
    s_static("\x00")

    s_initialize("TRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_static("mail")
    s_static("\x00")

    session.connect(s_get("RRQ"))
    session.connect(s_get("WRQ"))
    session.connect(s_get("TRQ"))

    session.fuzz()


if __name__ == "__main__":
    main()
```

