import errno
import socket
import sys

from boofuzz import exception
from boofuzz.connections import base_socket_connection


class TCPSocketConnection(base_socket_connection.BaseSocketConnection):
    """一个使用 TCP 套接字的 BaseSocketConnection 实现

    .. versionadded:: 0.2.0

    Args:
        host (str): 目标系统的主机名或 IP 地址。
        port (int): 目标服务的端口号。
        send_timeout (float): 超时前等待的发送秒数，默认为 5.0。
        recv_timeout (float): 超时前等待的接收秒数，默认为 5.0。
        server (bool): server 为真 表示启用服务端模糊测试。

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