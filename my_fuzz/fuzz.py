# Author: MirRoR4s
# Created: 2023/8/21
# Modified: 2023/8/21
import boofuzz
from boofuzz import Session as BoofuzzSession, Target, Request, Block, TCPSocketConnection, Bytes, Size, Byte
from TPKT import TPKT
from COTP import COTP
from S7Communication import S7Communication
from Session import Session

def h2b(m):
    if isinstance(m, str):
        return bytes.fromhex(m)
    elif isinstance(m, tuple):
        tmp = ''.join(m)
        return bytes.fromhex(tmp)
    else:
        print("Error! The Parameters's Type must be str or tuple.")
        return None


def define_proto(session: boofuzz.Session, tpkt: TPKT, cotp: COTP, s7comm: S7Communication):
    req = Request("S7COMM-Request", children=(
        Block("TPKT", children=(
            Byte("Version", default_value=h2b(tpkt.version),  max_num=2, fuzzable=True),
            Bytes("Reserved", default_value=h2b(tpkt.reserved), size=1, fuzzable=False),
            Size("test", block_name="COTP", offset=2, length=2, endian='>', inclusive=True,
                 fuzzable=False),  # 注意端序，注意长度字段本身也算进总长度内
            #  Bytes("Length", default_value=h2b(tpkt.length), size=2, fuzzable=False)
        )),
        Block("COTP", children=(
            Bytes("Length", default_value=h2b(cotp.length), size=1, fuzzable=False),
            Bytes("PDU Type", default_value=h2b(cotp.pdu_type), size=1, fuzzable=False),
            Bytes("DST Ref", default_value=h2b(cotp.destination_reference), size=2, fuzzable=False),
            Bytes("SRC Ref", default_value=h2b(cotp.source_reference), size=2, fuzzable=False),
            Bytes("Option", default_value=h2b(cotp.opt), size=1, fuzzable=False),
            Bytes("Parameters code", default_value=h2b(cotp.parameters)[:1], size=1, fuzzable=False),
            Bytes("Parameters length", default_value=h2b(cotp.parameters)[:2], size=1, fuzzable=False),
            Bytes("Parameters value", default_value=h2b(cotp.parameters)[:3], size=1, fuzzable=False),

            Block("S7COMM", children=(
                Bytes("Protocol ID", default_value=h2b(s7comm.protocol_id), size=1, fuzzable=False),
                Bytes("ROSCTR", default_value=h2b(s7comm.rosctr), size=1, fuzzable=False),
                Bytes("Reserved", default_value=h2b(s7comm.reserved), size=2, fuzzable=False),
                Bytes("PDU Reference", default_value=h2b(s7comm.pdu_reference), size=2, fuzzable=False),
                Bytes("Parameter Length", default_value=h2b(s7comm.parameter_length), size=2, fuzzable=False),
                Bytes("Data Length", default_value=h2b(s7comm.data_length), size=2, fuzzable=False),
                Bytes("Parameter", default_value=h2b(s7comm.parameter), fuzzable=False),
                Bytes("Data", default_value=h2b(s7comm.data), fuzzable=False)  # 对该字段进行模糊测试！
            ))
        )),
    ))

    session.connect(req)


def main():
    ip = "127.0.0.1"
    port = 102
    session = Session(ip, port)
    # session.send_setup_connection()
    # session.read_system_info()
    # session.read_clock()
    # s = connect(ip,port)
    tpkt,cotp,s7comm = session.send_cr_cc_tpdu()

    boofuzz_session = BoofuzzSession(
        target=Target(connection=TCPSocketConnection("127.0.0.1", 102)),
        sleep_time=1.0
    )

    define_proto(boofuzz_session, tpkt, cotp, s7comm)

    boofuzz_session.fuzz()


if __name__ == "__main__":
    main()
