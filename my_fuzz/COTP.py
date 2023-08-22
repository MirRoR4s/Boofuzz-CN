from S7Communication import S7Communication


class COTP:
    def __init__(
        self,
        length,
        pdu_type,
        opt: tuple,
        data: S7Communication = "",
        destination_reference="",
        source_reference="",
        parameters: tuple = ""  # 参数字段，由多个参数构成。

    ):
        """

        :param length:
        :param pdu_type:
        :param opt:
        :param data:
        :param destination_reference:
        :param source_reference:
        :param parameters:
        """
        self.length = length
        self.pdu_type = pdu_type
        self.opt = opt
        self.data = data
        self.destination_reference = destination_reference
        self.source_reference = source_reference
        self.parameters = parameters

    def __str__(self):
        """
        同S7COMM的__str__
        :return:
        """
        return (self.length + self.pdu_type + ''.join(i for i in self.opt) + str(self.data) + self.destination_reference
                + self.source_reference + ''.join(self.parameters))
