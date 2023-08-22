
class S7Communication:
    """

    """
    def __init__(
        self,
        protocol_id="",
        rosctr="",
        reserved="",
        pdu_reference="",
        parameter_length="",
        data_length="",
        parameter: tuple = "",  # 期望传入一个非空的字符串元组，若为空那么定义parameter为一个空字符串。
        data: tuple = ""

    ):
        """

        :param protocol_id:
        :param rosctr:
        :param reserved:
        :param pdu_reference:
        :param parameter_length:
        :param data_length:
        :param parameter:
        :param data:
        """
        self.protocol_id = protocol_id
        self.rosctr = rosctr
        self.reserved = reserved
        self.pdu_reference = pdu_reference
        self.parameter_length = parameter_length
        self.data_length = data_length
        self.parameter = parameter
        self.data = data

        if self.parameter_length != "":
            if int(parameter_length, 16) != len(''.join(parameter)) // 2:
                print("parameter length 可能有误，已尝试修正..")
                self.parameter_length = hex(len(''.join(parameter)) // 2)[2:].zfill(4)

    def __str__(self):
        """
        当S7COMM对象封装进COTP协议中时根据S7COMM对象的各成员变量将其转为字符串
        :return:
        """
        return (self.protocol_id + self.rosctr + self.reserved + self.pdu_reference + self.parameter_length
                + self.data_length + ''.join(self.parameter) + ''.join(self.data))

    def convert(self):
        tmp = vars(self)

        for key, value in tmp.items():
            tmp[key] = bytes.fromhex(value)

