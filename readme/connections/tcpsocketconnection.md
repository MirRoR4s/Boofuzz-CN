# TCPSocketConnection

TCPSocketConnection是BaseSocketConnection的TCP套接字实现。

```python
import errno
import socket
import sys

from boofuzz import exception
from boofuzz.connections import base_socket_connection


class TCPSocketConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with TCP Sockets.

    .. versionadded:: 0.2.0

    Args:
        host (str): Hostname or IP adress of target system.
        port (int): Port of target service.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        server (bool): Set to True to enable server side fuzzing.

    """

    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0, server=False):
        super(TCPSocketConnection, self).__init__(send_timeout, recv_timeout)

        self.host = host
        self.port = port
        self.server = server
        self._serverSock = None

    def close(self):
        super(TCPSocketConnection, self).close()

        if self.server:
            self._serverSock.close()

    def open(self):
        self._open_socket()
        self._connect_socket()

    def _open_socket(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # call superclass to set timeout sockopt
        super(TCPSocketConnection, self).open()

    def _connect_socket(self):
        if self.server:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self._sock.bind((self.host, self.port))
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    raise exception.BoofuzzOutOfAvailableSockets()
                else:
                    raise

            self._serverSock = self._sock
            try:
                self._serverSock.listen(1)
                self._sock, addr = self._serverSock.accept()
            except socket.error as e:
                # When connection timeout expires, tear down the server socket so we can re-open it again after
                # restarting the target.
                self.close()
                if e.errno in [errno.EAGAIN]:
                    raise exception.BoofuzzTargetConnectionFailedError(str(e))
                else:
                    raise
        else:
            try:
                self._sock.connect((self.host, self.port))
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    raise exception.BoofuzzOutOfAvailableSockets()
                elif e.errno in [errno.ECONNREFUSED, errno.EINPROGRESS, errno.ETIMEDOUT]:
                    raise exception.BoofuzzTargetConnectionFailedError(str(e))
                else:
                    raise

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        data = b""

        try:
            data = self._sock.recv(max_bytes)
        except socket.timeout:
            data = b""
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise exception.BoofuzzTargetConnectionAborted(
                    socket_errno=e.errno, socket_errmsg=e.strerror
                ).with_traceback(sys.exc_info()[2])
            elif (e.errno == errno.ECONNRESET) or (e.errno == errno.ENETRESET) or (e.errno == errno.ETIMEDOUT):
                raise exception.BoofuzzTargetConnectionReset().with_traceback(sys.exc_info()[2])
            elif e.errno == errno.EWOULDBLOCK:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                data = b""
            else:
                raise

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0

        try:
            num_sent = self._sock.send(data)
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise exception.BoofuzzTargetConnectionAborted(
                    socket_errno=e.errno, socket_errmsg=e.strerror
                ).with_traceback(sys.exc_info()[2])
            elif e.errno in [errno.ECONNRESET, errno.ENETRESET, errno.ETIMEDOUT, errno.EPIPE]:
                raise exception.BoofuzzTargetConnectionReset().with_traceback(sys.exc_info()[2])
            else:
                raise

        return num_sent

    @property
    def info(self):
        return "{0}:{1}".format(self.host, self.port)

```

构造函数参数：

* host（str）- 目标系统的域名或IP地址
* port（int）- 目标系统上的服务的端口号
* send\_timeout（float）- 发送超时前等待的秒数，默认为5.0
* recv\_tiemout（float）- 接收超时前等待的秒数，默认为5.0
* server（bool）- server为True时启用服务端fuzzing模糊测试

## 方法实现分析

> 针对类的各个成员方法的分析也要注意逻辑次序，比如关闭套接字之前肯定先要打开套接字。所以先分析open方法再分析close方法明显更加合乎逻辑，并且也能更好地观察到一些抽象变量的定义、赋值。

### open

```python
    def open(self):
        self._open_socket()
        self._connect_socket()
```

open封装了另外两个方法

### \_open\_socket

```python
    def _open_socket(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # call superclass to set timeout sockopt
        super(TCPSocketConnection, self).open()
```

创建一个基于 TCP/IP 的套接字（Socket）对象，并将其赋值给类中的 `_sock` 成员变量。

解释一下这段代码的具体含义：

1. `socket` 模块：这是 Python 提供的用于操作套接字的标准库。它允许我们创建网络连接、进行数据传输等操作。
2. `socket.socket` 函数：该函数用于创建一个套接字对象。它接受两个参数，分别是地址族（address family）和套接字类型（socket type）。
   * `socket.AF_INET`：表示 IPv4 地址族，用于指定套接字使用的 IP 地址格式。
   * `socket.SOCK_STREAM`：表示流式套接字类型，用于建立可靠的面向连接的数据传输，使用 TCP 协议。
3. `_sock` 成员变量：`self._sock` 是类中的一个成员变量，通常用来保存类的状态或需要在不同方法中共享的数据。在这里，它被赋值为一个新创建的 TCP 套接字对象。

通过以上代码，创建了一个 TCP/IP 套接字对象 `_sock`，可以使用它来建立与远程主机的连接，发送和接收数据。

```python
    @abc.abstractmethod
    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        Returns:
            None
        """
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _seconds_to_sockopt_format(self._send_timeout)) #  设置发送超时时间
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _seconds_to_sockopt_format(self._recv_timeout)) #  设置接收超时时间
```

```python
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
```
