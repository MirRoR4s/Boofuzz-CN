# Author: MirRoR4s
# Created: 2023/8/9
# Modified: 2023/8/9
from COTP import COTP


class TPKT:
    """

    """
    def __init__(self, version, reserved, length, data: COTP):
        """

        :param version:
        :param reserved:
        :param length:
        :param data:
        """
        self.version = version
        self.reserved = reserved
        self.length = length
        self.data = data

    def encapsulation(self):
        """
        封装数据包
        :return: 字节形式的封装完毕的数据包，可通过connect对象直接发送。
        """
        tmp = ''.join(str(i) for i in vars(self).values())

        if int(self.length, 16) != len(tmp) // 2:  # 长度是三种协议的总长
            print("Warning! The length of TPKT.length is wrong,try to fix it....")
            self.length = hex(len(tmp) // 2)[2:].zfill(4)

        return bytes.fromhex(''.join(str(i) for i in vars(self).values()))
