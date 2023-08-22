from pwn import connect
from S7Communication import S7Communication
from COTP import COTP
from TPKT import TPKT


class Session:
    """
    封装和发送各种功能的数据包
    """

    def __init__(self, ip, port):
        """

        :param ip: PLC IP地址
        :param port: PLC 端口号
        """
        self.ip = ip
        self.port = port
        self.socket = connect(ip, port)

    def send_cr_cc_tpdu(self):
        """
        暂未探究该数据包的作用
        :return:
        """
        s7comm = S7Communication()
        cotp = COTP(
            length="11",
            pdu_type="e0",
            opt=tuple("00"),
            data=s7comm,
            destination_reference="0000",
            source_reference="0001",
            parameters=("c0010a", "c1020100", "c2020102"))
        tpkt = TPKT(version="03", reserved="00", length="0016", data=cotp)

        self.socket.send(tpkt.encapsulation())
        recv = self.socket.recv().hex()  # 0300001611d00000000101c0010ac1020100c2020102
        print(recv)

        return tpkt, cotp, s7comm

    def send_setup_connection(self):
        """
        建立连接
        :return:
        """
        s7comm = S7Communication(
            protocol_id="32", rosctr="01", reserved="0000", pdu_reference="2400", parameter_length="0008",
            data_length="0000", parameter=("f0", "00", "0001", "0001", "01e0"), data=tuple(""))
        cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
        tpkt = TPKT(version="03", reserved="00", length="0019", data=cotp)
        self.socket.send(tpkt.encapsulation())
        recv = self.socket.recv().hex()
        print('Receive Setup Connection =', recv)

        return tpkt, cotp, s7comm

    def read_szl(self, szl_id, szl_index="0000"):
        """
        发送读取PLC的系统状态列表的数据包
        :param szl_id: 要读取的系统状态列表ID（十六进制字符串）
        :param szl_index: szl下标
        :return: 读取结果
        """
        s7comm = S7Communication(
            protocol_id="32", rosctr="07", reserved="0000", pdu_reference="4100", parameter_length="0008",
            data_length="0008", parameter=tuple("0001120411440100"), data=tuple("ff090004" + szl_id + szl_index))
        cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
        tpkt = TPKT(version="03", reserved="00", length="0021", data=cotp)

        self.socket.send(tpkt.encapsulation())
        recv = self.socket.recv().hex()
        print('Read {} ='.format(szl_id), recv)

        return tpkt,cotp,s7comm

    def read_system_info(self):
        """
        读取系统信息
        :return:
        """
        message1 = self.read_szl('0011')
        message2 = self.read_szl('001c')
        message3 = self.read_szl('0131', "0001")  # 注意SZL-Index不是0000了

        return message1, message2, message3

    def read_clock(self):
        """
        读取PLC时间
        :return:
        """
        s7comm = S7Communication(
            protocol_id="32", rosctr="07", reserved="0000", pdu_reference="4100", parameter_length="0008",
            data_length="0004", parameter=tuple("0001120411470100"), data=tuple("0a000000"))
        cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)

        tpkt = TPKT(version="03", reserved="00", length="001d", data=cotp)

        self.socket.send(tpkt.encapsulation())
        rec = self.socket.recv().hex()
        print('Read Clock =', rec)

        return tpkt, cotp, s7comm

    def data_read_and_write(
            self,
            area,
            address: int,  # Start
            length: int,  # Amount
            transport_size,  # WordLen
            db_number: int = 0,  # DB number
            flag=False,
            data="",
            asy=False
    ):
        """

        :param area: 要读写的区域
        :param address: 要读写区域的起始地址
        :param length: 读写长度
        :param transport_size: 读写单位，可以是字节、字、字符
        :param db_number: 数据块编号，当读写的不是数据块时，该字段为零
        :param flag: 标志位，flag=1表示是写入，否则为读取
        :param data: 要写入的数据
        :param asy: 标志位，asy=1表示异步写入
        :return:
        """
        if area != 'db' and db_number != 0:
            raise ValueError("When the Area isn't DB,the DB Number must be equal zero!")

        word_len_dictionary = {
            'bit': '01',  # 1
            'byte': '02',  # 8
            'char': '03',  # 8
            'word': '04',  # 8
            'int': '05',
            'd_word': '06',
            'd_int': '07',
            'real': '08',
            'date': '??',  # 暂时发现如何以date为单位读取
            'tod': '0a',
            'time': '0b',
            's5_time': '0c',
            'dt': '0d',
            'counter': '1c',
            'timer': '1d'

        }
        area_dictionary = {
            'db': '84',
            'digital_input': '81',
            'digital_output': '82',
            'merkers': '83',
            'timers': '1d',
            'counters': '1c'
        }
        word_len = word_len_dictionary.get(transport_size)
        area1 = area_dictionary.get(area)
        amount = hex(length)[2:].zfill(2 * 2)
        db_number1 = hex(db_number)[2:].zfill(2 * 2)

        if area != 'timer' and area != 'counter':
            start = hex(address * 8)[2:].zfill(3 * 2)  # start * word_len
        else:
            start = hex(address)[2:].zfill(6)

        function_code = "05" if flag else "04"
        s7comm = S7Communication(
            protocol_id="32", rosctr="01", reserved="0000", pdu_reference="4100", parameter_length="000e",
            data_length=hex(len(data) // 2)[2:].zfill(4),
            parameter=tuple(function_code + "01120a10" + word_len + amount + db_number1 + area1 + start),
            data=tuple(data)
        )
        cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
        tpkt = TPKT(version="03", reserved="00", length="0000", data=cotp)

        self.socket.send(tpkt.encapsulation())
        rec = self.socket.recv().hex()

        if flag:
            print('Write data = {} to {}{} where start = {} and amount = {}.'.format(rec, area, db_number, address,
                                                                                     length))
        else:
            print('Read data = {} from {}{} where start = {} and amount = {}.'.format(rec, area, db_number, address,
                                                                                      length))
        return tpkt, cotp, s7comm

    def db_get_and_fill(self, db_number, flag=False, data=""):
        """
        模拟数据块的获取和填充操作
        :param db_number: 要获取或填充的数据块号
        :param flag: 标志位。flag=1说明是填充，否则为获取。
        :param data: 填充数据
        :return:
        """
        s7comm = S7Communication(protocol_id="32", rosctr="07", reserved="0000", pdu_reference="1a0a",
                                 parameter_length="0008",
                                 data_length="000c", parameter=tuple("0001120411430300"),
                                 data=tuple("ff0900083041303030303" + str(db_number) + "41")
                                 )
        cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
        tpkt = TPKT(version="03", reserved="00", length="001d", data=cotp)
        self.socket.send(tpkt.encapsulation())
        rec = self.socket.recv().hex()
        print('Get Block Info =', rec)
        address_table = [0, 462, 924, 1386, 1848]

        for i in address_table:
            self.data_read_and_write(
                area="db", address=i, length=462 - int(flag) * 10,  # 写入时长度小10
                transport_size="byte", db_number=db_number,
                flag=flag, data=data
            )

    def control(self, command_index, asy=False):
        """
        控制PLC的工作状态
        :param command_index: 命令下标。当index=0时表示执行Get Stuats命令；当index=1表示执行Stop命令，其余以此类推。
        :param asy: 标志位，表明是否异步。
        :return:
        """
        if command_index == 0:
            self.read_szl("0424")
        elif command_index == 1:
            s7comm = S7Communication(
                protocol_id="32", rosctr="01", reserved="0000", pdu_reference="0a1a", parameter_length="0010",
                data_length="0000", parameter=tuple("29000000000009505f50524f4752414d")
            )
            cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
            tpkt = TPKT(version="03", reserved="00", length="0021", data=cotp)

            self.socket.send(tpkt.encapsulation())
            rec = self.socket.recv().hex()
            print('Execute Stop =', rec)
        elif command_index == 2:  # Hot Restart
            s7comm = S7Communication(
                protocol_id="32", rosctr="01", reserved="0000", pdu_reference="0a1a", parameter_length="0014",
                data_length="0000", parameter=tuple("28000000000000fd000009505f50524f4752414d")
            )
            cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
            tpkt = TPKT(version="03", reserved="00", length="0021", data=cotp)

            self.socket.send(tpkt.encapsulation())
            rec = self.socket.recv().hex()
            print('Hot Restart =', rec)
        elif command_index == 3:  # Cold Restart
            s7comm = S7Communication(
                protocol_id="32", rosctr="01", reserved="0000", pdu_reference="0a1a", parameter_length="0014",
                data_length="0000", parameter=tuple("28000000000000fd0002432009505f50524f4752414d")
            )
            cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
            tpkt = TPKT(version="03", reserved="00", length="0021", data=cotp)

            self.socket.send(tpkt.encapsulation())
            rec = self.socket.recv().hex()
            print('Cold Restart =', rec)
        elif command_index == 4:  # Copy RAM to ROM
            s7comm = S7Communication(
                protocol_id="32", rosctr="01", reserved="0000", pdu_reference="0a1a", parameter_length="0014",
                data_length="0000", parameter=tuple("28000000000000fd00024550055f4d4f4455")
            )
            cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
            tpkt = TPKT(version="03", reserved="00", length="0023", data=cotp)

            self.socket.send(tpkt.encapsulation())
            rec = self.socket.recv().hex()
            print('Copy RAM to ROM =', rec)
        elif command_index == 5:  # Compress
            s7comm = S7Communication(
                protocol_id="32", rosctr="01", reserved="0000", pdu_reference="0a1a", parameter_length="0014",
                data_length="0000", parameter=tuple("28000000000000fd0000055f47415242")
            )
            cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
            tpkt = TPKT(version="03", reserved="00", length="0021", data=cotp)

            self.socket.send(tpkt.encapsulation())
            rec = self.socket.recv().hex()
            print('Copy RAM to ROM =', rec)

            return tpkt, cotp, s7comm

    # def upload(self): # 待定，模拟器无法使用该功能

    # def download(self): # 待定，模拟器无法使用该功能

    def multi_read_and_write(
            self,
            area_table: tuple,
            address_table: tuple,  # Start
            length_table: tuple,  # Amount
            db_number_table: tuple,  # DB number
            flag=False,
            data_table: tuple = ("", "", "", "", ""),
            asy=False
    ):
        """
        批量读写PLC数据区域，比如数据块、数字量输入输出等
        :param area_table: 要读写的数据区域
        :param address_table: 数据区域的起始地址
        :param length_table: 读写的数据长度
        :param db_number_table: 当读写的是数据块时的数据块编号
        :param flag: 标志位。flag=1表示写入，否则表示读取。
        :param data_table: 数据表，包含待写入的数据。
        :param asy: 标志位。asy=1表示异步读写
        :return:
        """
        area_dictionary = {
            'db': '84',
            'digital_input': '81',
            'digital_output': '82',
            'merkers': '83',
            'timers': '1d',
            'counters': '1c'
        }
        function_code = "05" if flag else "04"  # 04是读，05是写

        if len(area_table) != 5 or len(address_table) != 5 or len(length_table) != 5 or len(db_number_table) != 5:
            raise ValueError("The length of Area isn't right,please check your setting and change the length to 5.")

        data_table1 = []

        for i, j in zip(length_table, data_table):
            data_table1.append(i * j)

        item_count = "05"
        item_data = ''.join("120a1002" +
                            hex(length_table[i])[2:].zfill(2 * 2) +
                            hex(db_number_table[i])[2:].zfill(2 * 2) +
                            area_dictionary.get(area_table[i]) +
                            hex(address_table[i] * 8)[2:].zfill(3 * 2)
                            for i in range(5)
                            )
        data = ''.join(
            "0004" +
            hex(length_table[i] * 8)[2:].zfill(2 * 2) +
            bytearray.fromhex(
                data_table1[i].zfill(
                    len(data_table1[i]) + 2 if (length_table[i] % 2 and i != len(length_table) - 1) else 0
                )
            )[::-1].hex() for i in range(5)
        ) if flag else ""

        s7comm = S7Communication(
            protocol_id="32", rosctr="01", reserved="0000", pdu_reference="4100", parameter_length="003e",
            data_length=hex(len(data) // 2)[2:].zfill(4),
            parameter=tuple(function_code + item_count + item_data),
            data=tuple(data)
        )
        cotp = COTP(length="02", pdu_type="f0", opt=tuple("80"), data=s7comm)
        tpkt = TPKT(version="03", reserved="00", length="0000", data=cotp)

        self.socket.send(tpkt.encapsulation())
        rec = self.socket.recv().hex()
        print(rec)

        return tpkt, cotp, s7comm
