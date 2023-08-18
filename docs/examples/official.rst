官方样例
========

FTP
---

1. 创建 Session 对象。
2. 构造原语，创建 Request 对象。
3. 连接 Request。
4. 进行模糊测试。

四个步骤中除了原语构造部分，其余都可以交给 boofuzz
框架来做，所以针对某个协议的模糊测试实质上要做的工作就是熟悉、了解协议以此构造出原语。

.. code:: python

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



   if __name__ == "__main__":
       main()
