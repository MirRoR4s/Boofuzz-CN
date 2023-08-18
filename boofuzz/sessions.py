import datetime
import errno
import itertools
import logging
import os
import pickle
import socket
import threading
import time
import traceback
import warnings
import zlib
from builtins import input
from io import open

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer

from boofuzz import (
    blocks,
    constants,
    event_hook,
    exception,
    fuzz_logger,
    fuzz_logger_curses,
    fuzz_logger_db,
    fuzz_logger_text,
    helpers,
    pgraph,
    primitives,
)
from boofuzz.monitors import CallbackMonitor
from boofuzz.mutation_context import MutationContext
from boofuzz.protocol_session import ProtocolSession
from boofuzz.web.app import app
from .exception import BoofuzzFailure


class Target:
    """Target descriptor container.

    Takes an ITargetConnection and wraps send/recv with appropriate
    FuzzDataLogger calls.

    Encapsulates pedrpc connection logic.

    Contains a logger which is configured by Session.add_target().

    Example:
        tcp_target = Target(SocketConnection(host='127.0.0.1', port=17971))

    Args:
        connection (itarget_connection.ITargetConnection): 到目标系统的连接对象
        monitors (List[Union[IMonitor, pedrpc.Client]]): 当前 Target 对象的监视器列表。
        monitor_alive: 当监视器处于活跃状态时会调用的一个函数列表
        repeater (repeater.Repeater): 发送时所用的 Repeater，默认为 None
        procmon: 用于添加进程监视器的接口（已弃用）
        procmon_options: 同上

    """

    def __init__(
        self,
        connection,
        monitors=None,
        monitor_alive=None,
        max_recv_bytes=10000,
        repeater=None,
        procmon=None,
        procmon_options=None,
        **kwargs
    ):
        self._fuzz_data_logger = None # 模糊测试数据记录器

        self._target_connection = connection
        self.max_recv_bytes = max_recv_bytes # 最大接收字节数
        self.repeater = repeater # repeater 是什么？或许类似于 Burp Repeater
        self.monitors = monitors if monitors is not None else []
        if procmon is not None:
            if procmon_options is not None:
                procmon.set_options(**procmon_options)
            self.monitors.append(procmon)

        self.monitor_alive = monitor_alive if monitor_alive is not None else []

        if "procmon" in kwargs.keys() and kwargs["procmon"] is not None:
            warnings.warn(
                "Target(procmon=...) is deprecated. Please change your code"
                " and add it to the monitors argument. For now, we do this "
                "for you, but this will be removed in the future.",
                FutureWarning,
            )
            self.monitors.append(kwargs["procmon"])

        if "netmon" in kwargs.keys() and kwargs["netmon"] is not None:
            warnings.warn(
                "Target(netmon=...) is deprecated. Please change your code"
                " and add it to the monitors argument. For now, we do this "
                "for you, but this will be removed in the future.",
                FutureWarning,
            )
            self.monitors.append(kwargs["netmon"])

        # set these manually once target is instantiated.
        """vmcontrol 应该和目标的重启有关，如果 vmcontrol 可用，那
        # 么就会恢复虚拟机快照。这个选项可能是在说明目标是运行在虚拟机中的。
        """
        self.vmcontrol = None 
        self.vmcontrol_options = {}

    @property
    def netmon_options(self):
        raise NotImplementedError(
            "This property is not supported; grab netmon from monitors and use set_options(**dict)"
        )

    @property
    def procmon_options(self):
        raise NotImplementedError(
            "This property is not supported; grab procmon from monitors and use set_options(**dict)"
        )

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._fuzz_data_logger.log_info("Closing target connection...")
        self._target_connection.close()
        self._fuzz_data_logger.log_info("Connection closed.")

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._fuzz_data_logger.log_info("Opening target connection ({0})...".format(self._target_connection.info))
        self._target_connection.open()
        self._fuzz_data_logger.log_info("Connection opened.")

    def pedrpc_connect(self):
        warnings.warn(
            "pedrpc_connect has been renamed to monitors_alive. "
            "This alias will stop working in a future version of boofuzz.",
            FutureWarning,
        )

        return self.monitors_alive()

    def monitors_alive(self):
        """
        等待监视器启动（活跃）/与 RPC 服务器建立连接。
        当某个 target 被添加到 session 中时，target 的每一次重启都会调用该方法。
        在成功 probing 后，会调用一个回调函数，并将 monitor 传进去。
        :return: None
        """
        for monitor in self.monitors:
            while True:
                if monitor.alive():
                    break
                time.sleep(1)

            if self.monitor_alive:
                for cb in self.monitor_alive:
                    cb(monitor)

    def recv(self, max_bytes=None):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        if max_bytes is None:
            max_bytes = self.max_recv_bytes

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("Receiving...")

        data = self._target_connection.recv(max_bytes=max_bytes)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_recv(data)

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            None
        """
        num_sent = 0
        if self._fuzz_data_logger is not None:
            repeat = ""
            if self.repeater is not None:
                repeat = ", " + self.repeater.log_message()

            self._fuzz_data_logger.log_info("Sending {0} bytes{1}...".format(len(data), repeat))

        if self.repeater is not None:
            self.repeater.start()
            while self.repeater.repeat():
                num_sent = self._target_connection.send(data=data)
            self.repeater.reset()
        else:
            num_sent = self._target_connection.send(data=data)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_send(data[:num_sent])

    def set_fuzz_data_logger(self, fuzz_data_logger):
        """
        设置当前 Target 对象的 fuzz 数据记录器--用于发送和接收 fuzz 数据。

        :param fuzz_data_logger: New logger.
        :type fuzz_data_logger: ifuzz_logger.IFuzzLogger

        :return: None
        """
        self._fuzz_data_logger = fuzz_data_logger


class Connection(pgraph.Edge):
    def __init__(self, src, dst, callback=None):
        """
        Extends pgraph.edge with a callback option. This allows us to register a function to call between node
        transmissions to implement functionality such as challenge response systems. The callback method must follow
        this prototype::

            def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as sesson.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet.

        Args:
            src (int): Edge source ID
            dst (int): Edge destination ID
            callback (function): Optional. Callback function to pass received data to between node xmits
        """

        super(Connection, self).__init__(src, dst)

        self.callback = callback


class SessionInfo:
    def __init__(self, db_filename):
        self._db_reader = fuzz_logger_db.FuzzLoggerDbReader(db_filename=db_filename)

    @property
    def monitor_results(self):
        return self._db_reader.failure_map

    @property
    def monitor_data(self):
        return {-1, "Monitor Data is not currently saved in the database"}

    @property
    def procmon_results(self):
        warnings.warn(
            "procmon_results has been renamed to monitor_results."
            "This alias will stop working in a future version of boofuzz",
            FutureWarning,
        )
        return self.monitor_results

    @property
    def netmon_results(self):
        warnings.warn(
            "netmon_results is now part of monitor_data" "This alias will stop working in a future version of boofuzz",
            FutureWarning,
        )
        return self.monitor_data

    @property
    def fuzz_node(self):
        return None

    @property
    def total_num_mutations(self):
        return None

    @property
    def total_mutant_index(self):
        x = next(self._db_reader.query("SELECT COUNT(*) FROM cases"))[0]
        return x

    @property
    def mutant_index(self):
        return None

    def test_case_data(self, index):
        """Return test case data object (for use by web server)

        Args:
            index (int): Test case index

        Returns:
            Test case data object
        """
        return self._db_reader.get_test_case_data(index=index)

    @property
    def is_paused(self):
        return False

    @property
    def state(self):
        return "finished"

    @property
    def exec_speed(self):
        return 0

    @property
    def runtime(self):
        return 0

    @property
    def current_test_case_name(self):
        return ""


class WebApp:
    """Serve fuzz data over HTTP.

    Args:
        session_info (SessionInfo): Object providing information on session
        web_port (int):         Port for monitoring fuzzing campaign via a web browser. Default 26000.
        web_address (string):   Address binded to port for monitoring fuzzing campaign via a web browser.
                                Default 'localhost'.
    """

    def __init__(
        self, session_info, web_port=constants.DEFAULT_WEB_UI_PORT, web_address=constants.DEFAULT_WEB_UI_ADDRESS
    ):
        self._session_info = session_info
        self._web_interface_thread = self._build_webapp_thread(port=web_port, address=web_address)
        pass

    def _build_webapp_thread(self, port, address):
        app.session = self._session_info
        http_server = HTTPServer(WSGIContainer(app))
        http_server.listen(port, address=address)
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread

    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc."""
        if not self._web_interface_thread.is_alive():
            # spawn the web interface.
            self._web_interface_thread.start()


def open_test_run(db_filename, port=constants.DEFAULT_WEB_UI_PORT, address=constants.DEFAULT_WEB_UI_ADDRESS):
    s = SessionInfo(db_filename=db_filename)
    w = WebApp(session_info=s, web_port=port, web_address=address)
    w.server_init()


class Session(pgraph.Graph):
    """继承自 pgraph.graph，为协议交互的构造提供了一个容器。

    Args:
        session_filename (str): 存放序列化数据的文件名，默认为 None
        index_start (int): 要运行的第一个测试用例的索引
        index_end (int): 要运行的最后一个测试用例的索引
        sleep_time (float):     测试用例之间等待的秒数，默认为 0
        restart_interval (int): 在 n 个测试用例之后重启目标。默认情况下为0，表示禁用该选项
        console_gui (bool):     是否使用 curses 在 web 端生成一个静态控制台，默认为 False（还未在 Windows 下进行测试）
        crash_threshold_request (int):  请求耗尽之前允许的最大崩溃次数，默认为 12。
        crash_threshold_element (int):  元素耗尽之前允许的最大崩溃次数，默认为 3
        restart_sleep_time (int): 当目标无法重启时等待的秒数，默认为5
        restart_callbacks (list of method): 在 `post_test_case_callback` 失败后调用的回调方法列表，默认为 None
        restart_threshold (int):    丢失目标连接时的最大重试次数，默认为 None（无限次）
        restart_timeout (float):    重新连接尝试的超时时间（秒），默认为 None（无限次）
        pre_send_callbacks (list of method): 在每个模糊（测试）请求之前调用的注册方法列表，默认为 None
        post_test_case_callbacks (list of method): 在每个模糊测试用例之后调用的注册方法列表，默认为None
        post_start_target_callbacks (list of method): 目标启动或重新启动后进程监视器调用的方法，默认为 None 。
        web_port (int or None): 通过 Web 浏览器监视模糊测试活动的端口。设置为 None 表示禁用 Web 应用程序，默认为 26000
        keep_web_open (bool): 在会话完成后保持 Web 界面打开，默认为 True
        fuzz_loggers (list of ifuzz_logger.IFuzzLogger): 日志记录器列表，用于保存测试数据和结果。默认将日志记录到 STDOUT 。
        fuzz_db_keep_only_n_pass_cases (int): Minimize disk usage by only saving passing test cases
                                              if they are in the n test cases preceding a failure or error.
                                              Set to 0 to save after every test case (high disk I/O!). Default 0.
        receive_data_after_each_request (bool): 如果为 True，在传输每个不进行模糊测试的节点后尝试接收回复，默认为True。
        check_data_received_each_request (bool): If True, Session will verify that some data has
                                                 been received after transmitting each non-fuzzed node, and if not,
                                                 register a failure. If False, this check will not be performed. Default
                                                 False. A receive attempt is still made unless
                                                 receive_data_after_each_request is False.
        receive_data_after_fuzz (bool): 如果该变量为真，那么在传输完一个 fuzzed 消息后，Session 会尝试接收一个响应
        ignore_connection_reset (bool): 将 ECONNREST 错误（目标连接复位）记录为 “info” 而非 failures
        ignore_connection_aborted (bool): 将ECONNABORTED错误记录为"info"而不是失败，默认为False。
        ignore_connection_issues_when_sending_fuzz_data (bool): 忽略发送模糊数据时的连接故障，默认为 True。这通常是一个有用的设置，因为目标一旦消息明显无效就可能会断开连接。
        ignore_connection_ssl_errors (bool): Log SSL related errors as "info" instead of failures. Default False.
        reuse_target_connection (bool): 如果为 True，则只使用一个目标连接（Target connection），而不是每个测试用例都重新连接。默认为 False。
        target (Target):        模糊（测试）会话的目标，必须完全初始化。默认为 None。
        db_filename (str):      存储测试结果和案例信息的 SQLite 数据库文件名。默认为 **./boofuzz-results/{uniq_timestamp}.db**。
        web_address:            Bofuzz 记录器对外的地址，默认为 localhost。
    """

    def __init__(
        self,
        session_filename=None,
        index_start=1,
        index_end=None,
        sleep_time=0.0,
        restart_interval=0,
        web_port=constants.DEFAULT_WEB_UI_PORT,
        keep_web_open=True,
        console_gui=False,
        crash_threshold_request=12,
        crash_threshold_element=3,
        restart_sleep_time=5,
        restart_callbacks=None,
        restart_threshold=None,
        restart_timeout=None,
        pre_send_callbacks=None,
        post_test_case_callbacks=None,
        post_start_target_callbacks=None,
        fuzz_loggers=None,
        fuzz_db_keep_only_n_pass_cases=0,
        receive_data_after_each_request=True,
        check_data_received_each_request=False,
        receive_data_after_fuzz=False,
        ignore_connection_reset=False,
        ignore_connection_aborted=False,
        ignore_connection_issues_when_sending_fuzz_data=True,
        ignore_connection_ssl_errors=False,
        reuse_target_connection=False,
        target=None,
        web_address=constants.DEFAULT_WEB_UI_ADDRESS,
        db_filename=None,
    ):
        self._ignore_connection_reset = ignore_connection_reset
        self._ignore_connection_aborted = ignore_connection_aborted
        self._ignore_connection_issues_when_sending_fuzz_data = ignore_connection_issues_when_sending_fuzz_data
        self._reuse_target_connection = reuse_target_connection
        self._ignore_connection_ssl_errors = ignore_connection_ssl_errors

        super(Session, self).__init__()

        self.session_filename = session_filename
        self._index_start = max(index_start, 1)
        self._index_end = index_end
        self.sleep_time = sleep_time
        self.restart_interval = restart_interval
        self.web_port = web_port
        self._keep_web_open = keep_web_open
        self.console_gui = console_gui
        self._crash_threshold_node = crash_threshold_request
        self._crash_threshold_element = crash_threshold_element
        self.restart_sleep_time = restart_sleep_time
        self.restart_threshold = restart_threshold
        self.restart_timeout = restart_timeout
        self.web_address = web_address
        if fuzz_loggers is None:
            fuzz_loggers = []
            if self.console_gui and os.name != "nt":
                fuzz_loggers.append(
                    fuzz_logger_curses.FuzzLoggerCurses(web_port=self.web_port, web_address=self.web_address)
                )
                self._keep_web_open = False
            else:
                fuzz_loggers = [fuzz_logger_text.FuzzLoggerText()]

        self._run_id = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(":", "-") # 运行 id，形如 '2023-08-17T02-47-17'
        if db_filename is not None:
            helpers.mkdir_safe(db_filename, file_included=True)
            self._db_filename = db_filename
        else:
            helpers.mkdir_safe(os.path.join(constants.RESULTS_DIR))
            self._db_filename = os.path.join(constants.RESULTS_DIR, "run-{0}.db".format(self._run_id))

        self._db_logger = fuzz_logger_db.FuzzLoggerDb(
            db_filename=self._db_filename, num_log_cases=fuzz_db_keep_only_n_pass_cases
        )

        self._crash_filename = "boofuzz-crash-bin-{0}".format(self._run_id)

        self._fuzz_data_logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self._db_logger] + fuzz_loggers)
        self._check_data_received_each_request = check_data_received_each_request
        self._receive_data_after_each_request = receive_data_after_each_request
        self._receive_data_after_fuzz = receive_data_after_fuzz
        self._skip_current_node_after_current_test_case = False
        self._skip_current_element_after_current_test_case = False
        self.start_time = time.time()
        self.end_time = None
        self.cumulative_pause_time = 0

        if self.web_port is not None:
            self.web_interface_thread = self.build_webapp_thread(port=self.web_port, address=self.web_address)

        if pre_send_callbacks is None:
            pre_send_methods = []
        else:
            pre_send_methods = pre_send_callbacks

        if post_test_case_callbacks is None:
            post_test_case_methods = []
        else:
            post_test_case_methods = post_test_case_callbacks

        if post_start_target_callbacks is None:
            post_start_target_methods = []
        else:
            post_start_target_methods = post_start_target_callbacks

        if restart_callbacks is None:
            restart_methods = []
        else:
            restart_methods = restart_callbacks

        self._callback_monitor = CallbackMonitor(
            on_pre_send=pre_send_methods,
            on_post_send=post_test_case_methods,
            on_restart_target=restart_methods,
            on_post_start_target=post_start_target_methods,
        )

        self.total_num_mutations = 0  # total available protocol mutations (before combining multiple mutations)
        self.total_mutant_index = 0  # index within all mutations iterated through, including skipped mutations
        self.mutant_index = 0  # index within currently mutating element
        self.num_cases_actually_fuzzed = 0
        self.fuzz_node = None  # Request object currently being fuzzed
        self.current_test_case_name = ""
        self.targets = []
        self.monitor_results = {}  # map of test case indices to list of crash synopsis strings (failed cases only)
        # map of test case indices to list of supplement captured data (all cases where data was captured)
        self.monitor_data = {}
        self.is_paused = False
        self.crashing_primitives = {}
        self.on_failure = event_hook.EventHook()

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root = pgraph.Node()
        self.root.label = "__ROOT_NODE__"
        self.root.name = self.root.label
        self.last_recv = None
        self.last_send = None

        self.add_node(self.root)

        if target is not None:

            def apply_options(monitor):
                monitor.set_options(crash_filename=self._crash_filename)

                return

            target.monitor_alive.append(apply_options)

            try:
                self.add_target(target)
            except exception.BoofuzzRpcError as e:
                self._fuzz_data_logger.log_error(str(e))
                raise

    @property
    def netmon_results(self):
        raise NotImplementedError(
            "netmon_results is now part of monitor_results and thus can't be accessed directly."
            " Please update your code."
        )

    def add_node(self, node):
        """
        将一个 pgraph 节点加入图中并自动生成分配一个 ID 给该节点。

        Args:
            node (pgraph.Node): 要加入会话图的节点
        """

        node.number = len(self.nodes)
        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def add_target(self, target):
        """
        将一个 target 加入到 session 中，可同时对多个目标进行模糊测试。

        Add a target to the session. Multiple targets can be added for parallel fuzzing.
        

        Args:
            target (Target): 要加入 session 的 Target 对象。
        """

        # pass specified target parameters to the PED-RPC server.
        target.monitors_alive()
        target.set_fuzz_data_logger(fuzz_data_logger=self._fuzz_data_logger)

        if self._callback_monitor not in target.monitors:
            target.monitors.append(self._callback_monitor)

        # add target to internal list.
        self.targets.append(target)

    def connect(self, src, dst=None, callback=None):
        """
        在两个 request（nodes）之间创建一个 Connection 对象并注册一个回调函数用于处理源请求和目的请求之间的传输过程。
        Session 类维持着一个顶级节点（根节点），所有的 requests 初始时都必须连接到该节点，例如：

    
        （Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. The session class maintains a top level node that all
        initial requests must be connected to. Example）
        ::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        
        如果仅给定了一个参数，那么 sess.connect() 默认会将该节点与根节点连接起来。

        （If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias. The following line is identical to the second line from the above example）
        ::

            sess.connect(s_get("HTTP"))

        
        利用回调方法来处理类似于挑战应答机制的情况。回调方法必须遵循 :meth:`Session.example_test_case_callback` 这样的消息签名，同时为了
        后续的兼容性，记得在参数中加上 \\*\\*kwargs。

        （Leverage callback methods to handle situations such as challenge response systems.
        A callback method must follow the message signature of :meth:`Session.example_test_case_callback`.
        Remember to include \\*\\*kwargs for forward-compatibility.）

        Args:
            src (str or Request (pgrah.Node)): 源 request 名称或 reques 节点。（Source request name or request node）
            dst (str or Request (pgrah.Node), optional): 目的 request 名称或节点。（Destination request name or request node）
            callback (def, optional): 回调函数。（Callback function to pass received data to between node xmits. Default None.）

        Returns:
            pgraph.Edge: src 和 dst 之间的边。（The edge between the src and dst.）
        """
        # if only a source was provided, then make it the destination and set the source to the root node.
        if dst is None:
            dst = src
            src = self.root

        # if source or destination is a name, resolve the actual node.
        if isinstance(src, str):
            src = self.find_node("name", src)

        if isinstance(dst, str):
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and self.find_node("name", src.name) is None:
            self.add_node(src)

        if self.find_node("name", dst.name) is None:
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = Connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge

    @property
    def exec_speed(self):
        return self.num_cases_actually_fuzzed / self.runtime

    @property
    def runtime(self):
        if self.end_time is not None:
            t = self.end_time
        else:
            t = time.time()
        return t - self.start_time - self.cumulative_pause_time

    def export_file(self):
        """
        Dump various object values to disk.

        :see: import_file()
        """

        if not self.session_filename:
            return

        data = {
            "session_filename": self.session_filename,
            "index_start": self.total_mutant_index,
            "sleep_time": self.sleep_time,
            "restart_sleep_time": self.restart_sleep_time,
            "restart_interval": self.restart_interval,
            "web_port": self.web_port,
            "web_address": self.web_address,
            "crash_threshold": self._crash_threshold_node,
            "total_num_mutations": self.total_num_mutations,
            "total_mutant_index": self.total_mutant_index,
            "monitor_results": self.monitor_results,
            "is_paused": self.is_paused,
        }

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(pickle.dumps(data, protocol=2)))
        fh.close()

    def _start_target(self, target):
        started = False
        for monitor in target.monitors:
            if monitor.start_target():
                started = True
                break
        if started:
            for monitor in target.monitors:
                monitor.post_start_target(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self)

    def import_file(self):
        """
        Load various object values from disk.

        :see: export_file()
        """
        if self.session_filename is None:
            return

        try:
            with open(self.session_filename, "rb") as f:
                data = pickle.loads(zlib.decompress(f.read()))
        except (IOError, zlib.error, pickle.UnpicklingError):
            return

        # update the skip variable to pick up fuzzing from last test case.
        self._index_start = data["total_mutant_index"]
        self.session_filename = data["session_filename"]
        self.sleep_time = data["sleep_time"]
        self.restart_sleep_time = data["restart_sleep_time"]
        self.restart_interval = data["restart_interval"]
        self.web_port = data["web_port"]
        self.web_address = data["web_address"]
        self._crash_threshold_node = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index = data["total_mutant_index"]
        self.monitor_results = data["monitor_results"]
        self.is_paused = data["is_paused"]

    def num_mutations(self, max_depth=None):
        """
        图中的总变异数。

        Number of total mutations in the graph. 
        
        该方法的逻辑与 fuzz() 是相同的，具体可参看 fuzz()。

        The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. 
        
        通过该方法可对 self.total_num_mutations 成员变量进行更新。

        The member variable self.total_num_mutations is updated appropriately by this routine.

        Args:
            max_depth (int): 模糊测试所用的最大组合深度。如果该值为 None 或者大于等于1，那么 num_mutations 返回 None，因为在使用组合模糊测试时，变异数通常是非常大的。（Maximum combinatorial depth used for fuzzing. num_mutations returns None if this value is None or greater than 1, as the number of mutations is typically very large when using combinatorial fuzzing.）
        
        Returns:
            int: 当前 session 对象的总变异数。（Total number of mutations in this session.）
        """
        if max_depth is None or max_depth > 1:
            self.total_num_mutations = None
            return self.total_num_mutations

        return self._num_mutations_recursive()

    def _num_mutations_recursive(self, this_node=None, path=None):
        """Helper for num_mutations.

        Args:
            this_node (request (node)): Current node that is being fuzzed. Default None.
            path (list): Nodes along the path to the current one being fuzzed. Default [].

        Returns:
            int: Total number of mutations in this session.
        """

        if this_node is None:
            this_node = self.root
            self.total_num_mutations = 0

        if path is None:
            path = []

        for edge in self.edges_from(this_node.id):
            next_node = self.nodes[edge.dst]
            self.total_num_mutations += next_node.get_num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self._num_mutations_recursive(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations

    def _pause_if_pause_flag_is_set(self):
        """
        If that pause flag is raised, enter an endless loop until it is lowered.
        """
        if self.is_paused:
            pause_start = time.time()
            while 1:
                if self.is_paused:
                    time.sleep(1)
                else:
                    break
            self.cumulative_pause_time += time.time() - pause_start

    def _check_for_passively_detected_failures(self, target, failure_already_detected=False):
        """Check for and log passively detected failures. Return True if any found.

        Args:
            target (Target): Target to be checked for failures.
            failure_already_detected (bool): If a failure was already detected.

        Returns:
            bool: True if failures were found. False otherwise.
        """
        has_crashed = False
        if len(target.monitors) > 0:
            self._fuzz_data_logger.open_test_step("Contact target monitors")
            # So, we need to run through the array two times. First, we check
            # if any of the monitors reported a failure and if so, we need to
            # gather a crash synopsis from them. We don't know whether
            # a monitor can provide a crash synopsis, but in any case, we'll
            # check. In the second run, we try to get crash synopsis from the
            # monitors that did not detect a crash as supplemental information.
            finished_monitors = []
            for monitor in target.monitors:
                if not monitor.post_send(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self):
                    has_crashed = True
                    self._fuzz_data_logger.log_fail(
                        "{0} detected crash on test case #{1}: {2}".format(
                            str(monitor), self.total_mutant_index, monitor.get_crash_synopsis()
                        )
                    )
                    finished_monitors.append(monitor)

            if not has_crashed and not failure_already_detected:
                self._fuzz_data_logger.log_pass("No crash detected.")
            else:
                for monitor in set(target.monitors) - set(finished_monitors):

                    synopsis = monitor.get_crash_synopsis()
                    if len(synopsis) > 0:
                        self._fuzz_data_logger.log_fail(
                            "{0} provided additional information for crash on #{1}: {2}".format(
                                str(monitor), self.total_mutant_index, monitor.get_crash_synopsis()
                            )
                        )
        return has_crashed

    def _get_monitor_data(self, target):
        """Query monitors for any data they may want to add to this test case.

        Args:
            target (Target): Monitor to query data from.
        """
        for monitor in target.monitors:
            data = monitor.retrieve_data()
            if data is not None and len(data) > 0:
                self._fuzz_data_logger.log_info(
                    "{0} captured {1} bytes of additional data for test case #{2}".format(
                        str(monitor), len(data), self.total_mutant_index
                    )
                )
                if self.total_mutant_index not in self.monitor_data:
                    self.monitor_data[self.total_mutant_index] = []

                self.monitor_data[self.total_mutant_index] += [data]

    def _process_failures(self, target):
        """Process any failures in self.crash_synopses.

        If self.crash_synopses contains any entries, perform these failure-related actions:
         - log failure summary if needed
         - save failures to self.monitor_results (for website)
         - exhaust node if crash threshold is reached
         - target restart

        Should be called after each fuzz test case.

        Args:
            target (Target): Target to restart if failure occurred.

        Returns:
            bool: True if any failures were found; False otherwise.
        """
        crash_synopses = self._fuzz_data_logger.failed_test_cases.get(self._fuzz_data_logger.most_recent_test_id, [])
        if len(crash_synopses) > 0:
            self._fuzz_data_logger.open_test_step("Failure summary")

            # retrieve the primitive that caused the crash and increment it's individual crash count.
            self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant, 0) + 1
            self.crashing_primitives[self.fuzz_node] = self.crashing_primitives.get(self.fuzz_node, 0) + 1

            # print crash synopsis
            if len(crash_synopses) > 1:
                # Prepend a header if > 1 failure report, so that they are visible from the main web page
                synopsis = "({0} reports) {1}".format(len(crash_synopses), "\n".join(crash_synopses))
            else:
                synopsis = "\n".join(crash_synopses)
            self.monitor_results[self.total_mutant_index] = crash_synopses
            self._fuzz_data_logger.log_info(synopsis)

            if (
                self.fuzz_node.mutant is not None
                and self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node
            ):
                skipped = max(0, self.fuzz_node.get_num_mutations() - self.mutant_index)
                self._skip_current_node_after_current_test_case = True
                self._fuzz_data_logger.open_test_step(
                    "Crash threshold reached for this request, exhausting {0} mutants.".format(skipped)
                )
                self.total_mutant_index += skipped
                self.mutant_index += skipped
            elif (
                self.fuzz_node.mutant is not None
                and self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element
            ):
                if not isinstance(self.fuzz_node.mutant, primitives.Group) and not isinstance(
                    self.fuzz_node.mutant, blocks.Repeat
                ):
                    skipped = max(0, self.fuzz_node.mutant.get_num_mutations() - self.mutant_index)
                    self._skip_current_element_after_current_test_case = True
                    self._fuzz_data_logger.open_test_step(
                        "Crash threshold reached for this element, exhausting {0} mutants.".format(skipped)
                    )
                    self.total_mutant_index += skipped
                    self.mutant_index += skipped

            self._restart_target(target)
            return True
        else:
            return False

    def register_post_test_case_callback(self, method):
        """Register a post- test case method.

        The registered method will be called after each fuzz test case.

        Potential uses:
         * Closing down a connection.
         * Checking for expected responses.

        The order of callback events is as follows::

            pre_send() - req - callback ... req - callback - post-test-case-callback

        Args:
            method (function): A method with the same parameters as :func:`~Session.post_send`
        """
        self._callback_monitor.on_post_send.append(method)

    # noinspection PyUnusedLocal
    def example_test_case_callback(self, target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
        """
        Example call signature for methods given to :func:`~Session.connect` or
        :func:`~Session.register_post_test_case_callback`

        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.
            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.
            test_case_context (ProtocolSession): Context for test case-scoped data.
                :py:class:`ProtocolSession` :py:attr:`session_variables <ProtocolSession.session_variables>`
                values are generally set within a callback and referenced in elements via default values of type
                :py:class:`ProtocolSessionReference`.
            args: Implementations should include \\*args and \\**kwargs for forward-compatibility.
            kwargs: Implementations should include \\*args and \\**kwargs for forward-compatibility.
        """
        # default to doing nothing.
        self._fuzz_data_logger.log_info("No post_send callback registered.")

    # noinspection PyMethodMayBeStatic
    def _pre_send(self, target):
        """
        Execute custom methods to run prior to each fuzz request. The order of events is as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        Args:
            target (session.target): Target we are sending data to
        """

        for monitor in target.monitors:
            try:
                self._fuzz_data_logger.open_test_step("Monitor {}.pre_send()".format(str(monitor)))
                monitor.pre_send(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self)
            except Exception:
                self._fuzz_data_logger.log_error(
                    constants.ERR_CALLBACK_FUNC.format(func_name="{}.pre_send()".format(str(monitor)))
                    + traceback.format_exc()
                )

    def _restart_target(self, target):
        """
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. If custom restart methods are registered, execute them. Otherwise, do nothing.

        Args:
            target (session.target): Target we are restarting

        Raises:
             exception.BoofuzzRestartFailedError: if restart fails.
        """

        # TODO: reuse_target_connection seems to be only handled when using
        #       a custom callback. wtf?

        self._fuzz_data_logger.open_test_step("Restarting target")
        restarted = False
        if len(self.on_failure) > 0:
            for f in self.on_failure:
                self._fuzz_data_logger.open_test_step("Calling registered on_failure method")
                f(logger=self._fuzz_data_logger)
            restarted = True
        # vm restarting is the preferred method so try that before monitors.
        elif target.vmcontrol:
            self._fuzz_data_logger.log_info("Restarting target virtual machine")
            target.vmcontrol.restart_target()
            restarted = True
        # we always have at least one monitor; a Callback Monitor that handles all callbacks.
        else:
            for monitor in target.monitors:
                self._fuzz_data_logger.log_info("Restarting target process using {}".format(monitor.__class__.__name__))
                if monitor.restart_target(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self):
                    # TODO: doesn't this belong in the process monitor?
                    self._fuzz_data_logger.log_info("Giving the process 3 seconds to settle in")
                    time.sleep(3)
                    restarted = True
                    break

        if restarted:
            for monitor in target.monitors:
                monitor.post_start_target(target=self.targets[0], fuzz_data_logger=self._fuzz_data_logger, session=self)
        else:
            self._fuzz_data_logger.log_info(
                "No reset handler available... sleeping for {} seconds".format(self.restart_sleep_time)
            )
            time.sleep(self.restart_sleep_time)

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        target.monitors_alive()

    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc."""
        if self.web_port is not None:
            if not self.web_interface_thread.is_alive():
                # spawn the web interface.
                self.web_interface_thread.start()

    def _callback_current_node(self, node, edge, test_case_context):
        """Execute callback preceding current node.

        Args:
            test_case_context (ProtocolSession): Context for test case-scoped data.
            node (pgraph.node.node (Node), optional): Current Request/Node
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.

        Returns:
            bytes: Data rendered by current node if any; otherwise None.
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self._fuzz_data_logger.open_test_step("Callback function '{0}'".format(edge.callback.__name__))
            data = edge.callback(
                self.targets[0],
                self._fuzz_data_logger,
                session=self,
                node=node,
                edge=edge,
                test_case_context=test_case_context,
            )

        return data

    def transmit_normal(self, sock, node, edge, callback_data, mutation_context):
        """Render and transmit a non-fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
            mutation_context (MutationContext): active mutation context
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render(mutation_context=mutation_context)

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.BoofuzzTargetConnectionReset:
            # TODO: Switch _ignore_connection_reset for _ignore_transmission_error, or provide retry mechanism
            if self._ignore_connection_reset:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            # TODO: Switch _ignore_connection_aborted for _ignore_transmission_error, or provide retry mechanism
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_aborted:
                self._fuzz_data_logger.log_info(msg)
            else:
                raise BoofuzzFailure(msg)
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                raise BoofuzzFailure(message=str(e))

        try:  # recv
            if self._receive_data_after_each_request:
                self.last_recv = self.targets[0].recv()

                if self._check_data_received_each_request:
                    self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                    if not self.last_recv:
                        # Assume a crash?
                        raise BoofuzzFailure(message="Nothing received from target.")
                    else:
                        self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.BoofuzzTargetConnectionReset:
            if self._check_data_received_each_request:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                raise BoofuzzFailure(msg)
            else:
                self._fuzz_data_logger.log_info(msg)
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                raise BoofuzzFailure(str(e))

    def transmit_fuzz(self, sock, node, edge, callback_data, mutation_context):
        """Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
            mutation_context (MutationContext): Current mutation context.
        """
        if callback_data:
            data = callback_data
        else:
            data = self.fuzz_node.render(mutation_context)

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.BoofuzzTargetConnectionReset:
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(msg)
            else:
                raise BoofuzzFailure(msg)
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                raise BoofuzzFailure(str(e))

        received = b""
        try:  # recv
            if self._receive_data_after_fuzz:
                received = self.targets[0].recv()
        except exception.BoofuzzTargetConnectionReset:
            if self._check_data_received_each_request:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                raise BoofuzzFailure(msg)
            else:
                self._fuzz_data_logger.log_info(msg)
            pass
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                self._fuzz_data_logger.log_fail(str(e))
                raise BoofuzzFailure(str(e))
        self.last_recv = received

    def build_webapp_thread(self, port=constants.DEFAULT_WEB_UI_PORT, address=constants.DEFAULT_WEB_UI_ADDRESS):
        """
        构建 web 应用程序进程，具体来说
        Session 对象作为 flask 实例的 session 属性，之后利用 Tornado 根据 flask 实例创建 http 服务。
        
        """
        app.session = self
        http_server = HTTPServer(WSGIContainer(app))
        while True:
            try:
                http_server.listen(port, address=address)
            except socket.error as exc:
                # Only handle "Address already in use"
                if exc.errno != errno.EADDRINUSE:
                    raise
                port += 1
            else:
                self._fuzz_data_logger.log_info("Web interface can be found at http://%s:%d" % (address, port))
                break
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread

    def feature_check(self):
        """Check all messages/features.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        for path in self._iterate_protocol_message_paths():
            self._message_check(path)

    def fuzz(self, name=None, max_depth=None):
        """对整个协议树进行模糊测试

        Fuzz the entire protocol tree.
        
        fuzz() 会遍历所有的 fuzz cases 并对其进行模糊测试，同时也会根据 self.skip 跳过一些元素以及根据 self.restart_interval 进行重启。


        Iterates through and fuzzes all fuzz cases, skipping according to
        self.skip and restarting based on self.restart_interval.
        
        
        If you want the web server to be available, your program must persist
        after calling this method. helpers.pause_for_signal() is
        available to this end.

        Args:
            name (str): 传入一个 Request 对象的名称来表明仅对该 request 消息进行模糊测试。Pass in a Request name to fuzz only a single request message. Pass in a test case name to fuzz
                        only a single test case.
            max_depth (int): Maximum combinatorial depth; set to 1 for "simple" fuzzing.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations(max_depth=max_depth)

        if name is None or name == "":
            self._main_fuzz_loop(self._generate_mutations_indefinitely(max_depth=max_depth))
        else:
            self.fuzz_by_name(name=name)

    def fuzz_by_name(self, name):
        """Fuzz a particular test case or node by name.

        Args:
            name (str): Name of node.
        """
        warnings.warn("Session.fuzz_by_name is deprecated in favor of Session.fuzz(name=name).")
        path, mutations = helpers.parse_test_case_name(name)
        if len(mutations) < 1:
            self._fuzz_single_node_by_path(path)
        else:
            self.total_mutant_index = 0
            self.total_num_mutations = 1

            node_edges = self._path_names_to_edges(node_names=path)
            self._main_fuzz_loop(self._generate_test_case_from_named_mutations(node_edges, mutations))

    def _fuzz_single_node_by_path(self, node_names):
        """Fuzz a particular node via the path in node_names.

        Args:
            node_names (list of str): List of node names leading to target.
        """
        node_edges = self._path_names_to_edges(node_names=node_names)

        self.total_mutant_index = 0
        self.total_num_mutations = self.nodes[node_edges[-1].dst].get_num_mutations()

        self._main_fuzz_loop(self._generate_mutations_indefinitely(path=node_edges))

    def fuzz_single_case(self, mutant_index):
        """Deprecated: Fuzz a test case by mutant_index.

        Deprecation note: The new approach is to set Session's start and end indices to the same value.

        Args:
            mutant_index (int): Positive non-zero integer.

        Returns:
            None

        Raises:
            sex.SulleyRuntimeError: If any error is encountered while executing the test case.
        """
        warnings.warn(
            "Session.fuzz_single_case is deprecated in favor of Session's index_start and index_end constructor "
            "parameters."
        )
        self.total_mutant_index = 0
        self.total_num_mutations = 1

        self._main_fuzz_loop(self._generate_single_case_by_index(mutant_index))

    def _message_check(self, path):
        """Check messages for compatibility.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            path (list of Connection): Nodes (Requests) along the path to the target one.

        Returns:
            None
        """
        self.server_init()

        try:
            self._check_message(MutationContext(message_path=path, mutations={}))
        except KeyboardInterrupt:
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.BoofuzzRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.BoofuzzTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def _main_fuzz_loop(self, fuzz_case_iterator):
        """执行主要的模糊测试逻辑，以一个可迭代的 test cases 作为参数。

        
        Execute main fuzz logic; takes an iterator of test cases.
        

        调用条件：`self.total_mutant_index` and `self.total_num_mutations` 都已正确设置。


        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        
        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through fuzz cases and yields MutationContext objects.
                 See _iterate_single_node() for details.

        Returns:
            None
        """
        self.server_init()

        try:
            self._start_target(self.targets[0])

            if self._reuse_target_connection:
                self.targets[0].open()
            self.num_cases_actually_fuzzed = 0
            self.start_time = time.time()
            for mutation_context in fuzz_case_iterator:
                if self.total_mutant_index < self._index_start:
                    continue

                # Check restart interval
                if (
                    self.num_cases_actually_fuzzed
                    and self.restart_interval
                    and self.num_cases_actually_fuzzed % self.restart_interval == 0
                ):
                    self._fuzz_data_logger.open_test_step("restart interval of %d reached" % self.restart_interval)
                    self._restart_target(self.targets[0])

                self._fuzz_current_case(mutation_context)

                self.num_cases_actually_fuzzed += 1

                if self._index_end is not None and self.total_mutant_index >= self._index_end:
                    break

            if self._reuse_target_connection:
                self.targets[0].close()

            if self._keep_web_open and self.web_port is not None:
                self.end_time = time.time()
                print(
                    "\nFuzzing session completed. Keeping webinterface up on {}:{}".format(
                        self.web_address, self.web_port
                    ),
                    "\nPress ENTER to close webinterface",
                )
                input()
        except KeyboardInterrupt:
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.BoofuzzRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.BoofuzzTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise
        finally:
            self._fuzz_data_logger.close_test()

    def _generate_single_case_by_index(self, test_case_index):
        fuzz_index = 1
        for m in self._generate_mutations_indefinitely():
            if fuzz_index >= test_case_index:
                self.total_mutant_index = 1
                yield m
                break
            fuzz_index += 1

    def _generate_mutations_indefinitely(self, max_depth=None, path=None):
        """
        在所有消息中，每条消息产生具有 n 个变异的 MutationContext 对象，n 的值会无限增加。

        （Yield MutationContext with n mutations per message over all messages, with n increasing indefinitely.）"""
        depth = 1
        while max_depth is None or depth <= max_depth:
            valid_case_found_at_this_depth = False
            for m in self._generate_n_mutations(depth=depth, path=path):
                valid_case_found_at_this_depth = True
                yield m
            if not valid_case_found_at_this_depth:
                break
            depth += 1

    def _generate_n_mutations(self, depth, path):
        """
        对所有消息来说，每个消息都利用 n 个 变异产生一个 MutationContext 对象。

        Yield MutationContext with n mutations per message over all messages."""
        for path in self._iterate_protocol_message_paths(path=path):
            for m in self._generate_n_mutations_for_path(path, depth=depth):
                yield m

    def _generate_n_mutations_for_path(self, path, depth):
        """
        利用 n 个变异产生某个特定消息（实质上对应着一条边即一个 Connection 对象）的 MutationContext 对象。

        Yield MutationContext with n mutations for a specific message.

        Args:
            path (list of Connection): Nodes (Requests) along the path to the current one being fuzzed.
            depth (int): Yield sets of depth mutations.

        Yields:
            MutationContext: 包含着一个变异的 MutationContext 对象。（A MutationContext containing one mutation.）
        """
        for mutations in self._generate_n_mutations_for_path_recursive(path, depth=depth):
            if not self._mutations_contain_duplicate(mutations):
                self.total_mutant_index += 1
                yield MutationContext(message_path=path, mutations={n.qualified_name: n for n in mutations})

    def _generate_n_mutations_for_path_recursive(self, path, depth, skip_elements=None):
        if skip_elements is None:
            skip_elements = set()
        if depth == 0:
            yield []
            return
        new_skip = skip_elements.copy()
        for mutations in self._generate_mutations_for_request(path=path, skip_elements=skip_elements):
            new_skip.update(m.qualified_name for m in mutations)
            for ms in self._generate_n_mutations_for_path_recursive(path, depth=depth - 1, skip_elements=new_skip):
                yield mutations + ms

    def _iterate_protocol_message_paths(self, path=None):
        """
        遍历协议并产生一条到达某个给定消息的路径。（Connection 对象的列表）

        Iterates over protocol and yields a path (list of Connection) leading to a given message).

        Args:
            path (list of Connection): Provide a specific path to yield only that specific path.

        Yields:
            list of Connection: 沿着当前路径到达当前被 fuzzed 节点的边列表。（List of edges along the path to the current one being fuzzed.）

        Raises:
            exception.SulleyRuntimeError: If no requests defined or no targets specified
        """
        # we can't fuzz if we don't have at least one target and one request.
        if not self.targets:
            raise exception.SullyRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id): # 获得从给定节点开始的所有边，以列表的形式返回。
            raise exception.SullyRuntimeError("No requests specified in session")

        if path is not None:
            yield path
        else:
            for x in self._iterate_protocol_message_paths_recursive(this_node=self.root, path=[]):
                yield x

    def _iterate_protocol_message_paths_recursive(self, this_node, path):
        """
        
        Recursive helper for _iterate_protocol.

        Args:
            this_node (node.Node): 当前正被模糊测试的节点。（Current node that is being fuzzed.）
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        Yields:
            list of Connection: List of edges along the path to the current one being fuzzed.
        """
        # 获得以当前节点为起点的所有边。step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we fuzz through it, don't count the root node.

            # 我们保持与节点相对应的边的追踪，因为如果存在超过一条路径通过了一个给定节点的集合，那么我们不想要任何的二义性。
            
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = self._message_path_to_str(path)
            logging.debug("fuzzing: {0}".format(message_path))
            self.fuzz_node = self.nodes[path[-1].dst]

            yield path

            # 递归地对会话图中的剩余节点进行模糊测试。recursively fuzz the remainder of the nodes in the session graph.
            for x in self._iterate_protocol_message_paths_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _mutations_contain_duplicate(self, mutations):
        names = [m.qualified_name for m in mutations]
        for name1, name2 in itertools.combinations(names, r=2):
            if name1 in name2 or name2 in name1:
                return True
        return False

    def _generate_mutations_for_request(self, path, skip_elements=None):
        """
        

        Yield each mutation for a specific message (the last message in path).

        Args:
            path (list of Connection): Nodes (Requests) along the path to the current one being fuzzed.
            path (iter of str): Qualified names of elements to skip while fuzzing.

        Yields:
            Mutation: 描述单个变异的 Mutation 对象。（Mutation object describing a single mutation.）
        """
        if skip_elements is None:
            skip_elements = []
        self.fuzz_node = self.nodes[path[-1].dst]
        self.mutant_index = 0

        for mutations in self.fuzz_node.get_mutations(skip_elements=skip_elements):
            self.mutant_index += 1
            yield mutations

            if self._skip_current_node_after_current_test_case:
                self._skip_current_node_after_current_test_case = False
                break
            elif self._skip_current_element_after_current_test_case:
                self.fuzz_node.mutant.stop_mutations()
                self._skip_current_element_after_current_test_case = False
                continue

    def _generate_test_case_from_named_mutations(self, path, mutation_names):
        # need a way to get the mutation value based on the mutation index
        self.fuzz_node = self.nodes[path[-1].dst]
        self.mutant_index = 0

        mutations = []
        for mutation_name in mutation_names:
            qualified_name, index = mutation_name.rsplit(":")
            index = int(index)
            fuzzable = self.fuzz_node.names[qualified_name]
            mutations += next(itertools.islice(fuzzable.get_mutations(), index, index + 1))
        self.total_mutant_index += 1
        yield MutationContext(message_path=path, mutations={n.qualified_name: n for n in mutations})

    def _path_names_to_edges(self, node_names):
        """Take a list of node names and return a list of edges describing that path.

        Args:
            node_names (list of str): List of node names describing a path.

        Returns:
            list of Connection: List of edges describing the path in node_names.
        """
        cur_node = self.root
        edge_path = []
        for node_name in node_names:
            next_node = None
            for edge in self.edges_from(cur_node.id):
                if self.nodes[edge.dst].name == node_name:
                    edge_path.append(edge)
                    next_node = self.nodes[edge.dst]
                    break
            if next_node is None:
                raise Exception("No edge found from {0} to {1}".format(cur_node.name, node_name))
            else:
                cur_node = next_node
        return edge_path

    def _check_message(self, mutation_context):
        """Sends the current message without fuzzing.

        Current test case is controlled by fuzz_case_iterator().

        Args:
            mutation_context (MutationContext): Current mutation context.
        """
        target = self.targets[0]
        self.total_mutant_index += 1

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name_feature_check(mutation_context)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name,
            index=self.total_mutant_index,
            num_mutations=self.total_num_mutations,
            current_index=self.mutant_index,
            current_num_mutations=self.fuzz_node.get_num_mutations(),
        )

        try:
            self._open_connection_keep_trying(target)
            self._pre_send(target)

            for e in mutation_context.message_path[:-1]:
                prev_node = self.nodes[e.src]
                node = self.nodes[e.dst]
                protocol_session = ProtocolSession(
                    previous_message=prev_node,
                    current_message=node,
                )
                mutation_context.protocol_session = protocol_session
                self._fuzz_data_logger.open_test_step("Prep Node '{0}'".format(node.name))
                callback_data = self._callback_current_node(node=node, edge=e, test_case_context=protocol_session)
                self.transmit_normal(target, node, e, callback_data=callback_data, mutation_context=mutation_context)

            prev_node = self.nodes[mutation_context.message_path[-1].src]
            node = self.nodes[mutation_context.message_path[-1].dst]
            protocol_session = ProtocolSession(
                previous_message=prev_node,
                current_message=node,
            )
            mutation_context.protocol_session = protocol_session
            callback_data = self._callback_current_node(
                node=self.fuzz_node, edge=mutation_context.message_path[-1], test_case_context=protocol_session
            )

            self._fuzz_data_logger.open_test_step("Node Under Test '{0}'".format(self.fuzz_node.name))
            self.transmit_normal(
                target,
                self.fuzz_node,
                mutation_context.message_path[-1],
                callback_data=callback_data,
                mutation_context=mutation_context,
            )

            self._check_for_passively_detected_failures(target)
            if not self._reuse_target_connection:
                target.close()

            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
                time.sleep(self.sleep_time)
        finally:
            if self._process_failures(target=target):
                print("FAIL: {0}".format(test_case_name))
            else:
                print("PASS: {0}".format(test_case_name))

            self._get_monitor_data(target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()

    def _fuzz_current_case(self, mutation_context):
        """
        Fuzzes the current test case. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            mutation_context (MutationContext): Current mutation context.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name(mutation_context)
        self.current_test_case_name = test_case_name

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name,
            index=self.total_mutant_index,
            num_mutations=self.total_num_mutations,
            current_index=self.mutant_index,
            current_num_mutations=self.fuzz_node.get_num_mutations(),
        )

        if self.total_num_mutations is not None:
            self._fuzz_data_logger.log_info(
                "Type: {0}. Case {1} of {2} overall.".format(
                    type(self.fuzz_node.mutant).__name__,
                    self.total_mutant_index,
                    self.total_num_mutations,
                )
            )
        else:
            self._fuzz_data_logger.log_info(
                "Type: {0}".format(
                    type(self.fuzz_node.mutant).__name__,
                )
            )

        try:
            self._open_connection_keep_trying(target)

            self._pre_send(target)

            for e in mutation_context.message_path[:-1]:
                prev_node = self.nodes[e.src]
                node = self.nodes[e.dst]
                protocol_session = ProtocolSession(
                    previous_message=prev_node,
                    current_message=node,
                )
                mutation_context.protocol_session = protocol_session
                callback_data = self._callback_current_node(node=node, edge=e, test_case_context=protocol_session)
                self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                self.transmit_normal(target, node, e, callback_data=callback_data, mutation_context=mutation_context)

            prev_node = self.nodes[mutation_context.message_path[-1].src]
            node = self.nodes[mutation_context.message_path[-1].dst]
            protocol_session = ProtocolSession(
                previous_message=prev_node,
                current_message=node,
            )
            mutation_context.protocol_session = protocol_session
            callback_data = self._callback_current_node(
                node=self.fuzz_node, edge=mutation_context.message_path[-1], test_case_context=protocol_session
            )
            self._fuzz_data_logger.open_test_step("Fuzzing Node '{0}'".format(self.fuzz_node.name))
            self.transmit_fuzz(
                target,
                self.fuzz_node,
                mutation_context.message_path[-1],
                callback_data=callback_data,
                mutation_context=mutation_context,
            )

            self._check_for_passively_detected_failures(target=target)
            if not self._reuse_target_connection:
                target.close()

            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._sleep(self.sleep_time)
        except BoofuzzFailure as e:
            self._fuzz_data_logger.log_fail(e.message)
            self._check_for_passively_detected_failures(target=target, failure_already_detected=True)
        finally:
            self._process_failures(target=target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()

    def _open_connection_keep_trying(self, target):
        """Open connection and if it fails, keep retrying.

        Args:
            target (Target): Target to open.
        """
        if not self._reuse_target_connection:
            out_of_available_sockets_count = 0
            unable_to_connect_count = 0
            initial_time = time.time()

            while True:
                try:
                    target.open()
                    break  # break if no exception
                except exception.BoofuzzTargetConnectionFailedError:
                    if self.restart_threshold and unable_to_connect_count >= self.restart_threshold:
                        self._fuzz_data_logger.log_info(
                            "Unable to reconnect to target: Reached threshold of {0} retries. Ending fuzzing.".format(
                                self.restart_threshold
                            )
                        )
                        raise
                    elif self.restart_timeout and time.time() >= initial_time + self.restart_timeout:
                        self._fuzz_data_logger.log_info(
                            "Unable to reconnect to target: Reached restart timeout of {0}s. Ending fuzzing.".format(
                                self.restart_timeout
                            )
                        )
                        raise
                    else:
                        self._fuzz_data_logger.log_info(constants.WARN_CONN_FAILED_TERMINAL)
                        self._restart_target(target)
                        unable_to_connect_count += 1
                except exception.BoofuzzOutOfAvailableSockets:
                    out_of_available_sockets_count += 1
                    if out_of_available_sockets_count == 50:
                        raise exception.BoofuzzError("There are no available sockets. Ending fuzzing.")
                    self._fuzz_data_logger.log_info("There are no available sockets. Waiting for another 5 seconds.")
                    time.sleep(5)

    def _sleep(self, seconds):
        self._fuzz_data_logger.log_info("sleeping for %f seconds" % seconds)
        time.sleep(seconds)

    def _test_case_name_feature_check(self, mutation_context):
        message_path = self._message_path_to_str(mutation_context.message_path)
        return "FEATURE-CHECK->{0}".format(message_path)

    def _test_case_name(self, mutation_context):
        """Get long test case name.

        Args:
            mutation_context (MutationContext): MutationContext to get name from.

        Returns:
            Long formatted test case name
        """
        message_path = self._message_path_to_str(mutation_context.message_path)
        mutation_names = (
            "{0}:{1}".format(qualified_name, mutation.index)
            for qualified_name, mutation in mutation_context.mutations.items()
        )
        return "{0}:[{1}]".format(message_path, ", ".join(mutation_names))

    def _message_path_to_str(self, message_path):
        return "->".join([self.nodes[e.dst].name for e in message_path])

    def test_case_data(self, index):
        """Return test case data object (for use by web server)

        Args:
            index (int): Test case index

        Returns:
            DataTestCase: Test case data object
        """
        return self._db_logger.get_test_case_data(index=index)
