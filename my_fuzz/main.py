from Session import Session


def main():

    ip = "127.0.0.1"
    port = 102
    session = Session(ip, port)
    # session.send_setup_connection()
    # session.read_system_info()
    # session.read_clock()
    # s = connect(ip,port)
    session.send_cr_cc_tpdu()
    # send_setup_connection(s)
    # read_szl(s,"0000")
    # read_szl(s,"0f00")
    # read_system_info(s)
    # read_clock(s)
    # session.data_read_and_write(area='db',address=2,length=2,transport_size='byte',db_number=1,flag=True,data="000400100000")
    # session.db_get_and_fill(2,flag=False,data="")
    # session.control(5)
    # session.multi_read_and_write(
    #         area_table=('digital_input','db','db','db','db'),
    #         address_table=(1,1,1,1,1),
    #         length_table=(15,16,16,16,16),
    #         db_number_table=(0,2,3,4,5),
    # )
    # session.multi_read_and_write(
    #         area_table=('db', 'db', 'db', 'digital_input', 'digital_output'),
    #         address_table=(0, 0, 0, 0, 0),
    #         length_table=(1, 2, 3, 4, 5),
    #         db_number_table=(1, 2, 3, 0, 0),
    #         flag=True,
    #         data_table=("01", "02", "03", "04", "05")
    # )
    # session.interactive()

# Press the green button in the gutter to run the script.


if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
