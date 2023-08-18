import abc
import math
import os
import socket
import struct

from boofuzz.connections import itarget_connection


def _seconds_to_sockopt_format(seconds):
    """Convert floating point seconds value to second/useconds struct used by UNIX socket library.
    For Windows, convert to whole milliseconds.
    """
    if os.name == "nt":
        return int(seconds * 1000)
    else:
        microseconds_per_second = 1000000
        whole_seconds = int(math.floor(seconds))
        whole_microseconds = int(math.floor((seconds % 1) * microseconds_per_second))
        return struct.pack("ll", whole_seconds, whole_microseconds)


class BaseSocketConnection(itarget_connection.ITargetConnection, metaclass=abc.ABCMeta):
    """
    BaseSocketConnection 是大量套接字连接类的基类，定义了几个抽象方法，比如 open()、close() 等。

    该类有一个内部成员变量 _sock，目前还不知道起何种作用。


    .. This class serves as a base for a number of Connections over sockets.

    .. versionadded:: 0.2.0

    Args:
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
    """

    def __init__(self, send_timeout, recv_timeout):
        self._send_timeout = send_timeout
        self._recv_timeout = recv_timeout

        self._sock = None

    def close(self):
        """
        关闭到目标的连接。

        .. Close connection to the target.

        Returns:
            None
        """
        self._sock.close()

    @abc.abstractmethod
    def open(self):
        """
        作者原意是说打开到目标的连接并且提醒我们最后调用 close() 关闭连接。不过从源码看出来 BaseSocketConnection 类的 open() 方法
        其实是在设置套接字的选项。

        .. Opens connection to the target. Make sure to call close!

        Returns:
            None
        """
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _seconds_to_sockopt_format(self._send_timeout)) # 
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _seconds_to_sockopt_format(self._recv_timeout))
