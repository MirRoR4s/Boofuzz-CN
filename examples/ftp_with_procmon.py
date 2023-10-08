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
    
    这个例子是一个使用了进程监视器 (procmon) 的非常简单的 FTP 模糊器。它假定 procmon 已处于运行状态。
    该脚本将连接到 procmon ，并告诉 procmon 启动目标应用程序(参见 start_cmd )。
    
    `start_cmd` 中的 ftpd.py 是一个使用 pyftpdlib 的简单 FTP 服务器。
    你可以用任何 FTP 服务器来替代它。
    
    该脚本的用法应是首先连接到 RPC 服务端，然后发送 start_cmd 命令让 RPC 服务端启动一个 ftp 服务器。
    所以我们需要先编写一个 RPC 服务端，然后再编写一个 ftp 服务器，最后运行本脚本即可。
    """
    target_ip = "127.0.0.1"
    start_cmd = ["python", "C:\\ftpd\\ftpd.py"]

    # initialize the process monitor  初始化进程监视器
    # this assumes that prior to starting boofuzz you started the process monitor  假设 boofuzz 先于进程监视器启动
    # RPC daemon!  RPC 后台守护进程！
    procmon = ProcessMonitor(target_ip, 26002)
    procmon.set_options(start_commands=[start_cmd])  # 实际调用的是 set_start_commands(start_cmd)? 存疑！

    # We configure the session, adding the configured procmon to the monitors.  配置 session，将已配置好的进程监视器添加到 monitors 中
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
