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

可以对官方给出的样例进行动态调试，以此学习 Boofuzz 源码实现。

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

FTP With Procmon
----------------

通过研究官方给出的带有监视器的 FTP
协议模糊测试脚本，可以了解监视器的使用步骤和方法。不过可惜的是官方给出的脚本是依照旧的协议格式写的，后续的话笔者可能会转成新的。

阅读源码中的注释可以明白，此处的监视器其实就是一个启动 ftp
服务器的脚本。

.. code:: python

   #!/usr/bin/env python3
   # Designed for use with boofuzz v0.2.0

   from boofuzz import *


   def main():
       """
       This example is a very simple FTP fuzzer using a process monitor (procmon).
       It assumes that the procmon is already running. The script will connect to
       the procmon and tell the procmon to start the target application
       (see start_cmd).

       The ftpd.py in `start_cmd` is a simple FTP server using pyftpdlib. You can
       substitute any FTP server.
       """
       target_ip = "127.0.0.1"
       start_cmd = ["python", "C:\\ftpd\\ftpd.py"]

       # initialize the process monitor
       # this assumes that prior to starting boofuzz you started the process monitor
       # RPC daemon!
       procmon = ProcessMonitor(target_ip, 26002)
       procmon.set_options(start_commands=[start_cmd])

       # We configure the session, adding the configured procmon to the monitors.
       # fmt: off
       session = Session(
           target=Target(
               connection=TCPSocketConnection(target_ip, 21),
               monitors=[procmon],
           ),
           sleep_time=1,
       )
       # fmt: on

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

       session.fuzz()


   if __name__ == "__main__":
       main()

在这里给出一个 gpt 编写的 ftp 服务器搭建脚本

.. code:: python

   # Author: MirRoR4s
   # Created: 2023/8/18
   # Modified: 2023/8/18
   from pyftpdlib.authorizers import DummyAuthorizer
   from pyftpdlib.handlers import FTPHandler
   from pyftpdlib.servers import FTPServer

   # 设置用户认证信息
   authorizer = DummyAuthorizer()
   authorizer.add_user("username", "password", "./ftp", perm="elradfmw")

   # 设置匿名用户权限（如果需要）
   authorizer.add_anonymous("./ftp/anonymous")

   # 创建 FTP 处理器和服务器
   handler = FTPHandler
   handler.authorizer = authorizer
   server = FTPServer(("0.0.0.0", 26002), handler)

   # 启动 FTP 服务器
   server.serve_forever()
