# init

## 分析

### init

```python
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

        self._run_id = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(":", "-")
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
```

| 名称                        | 类型             | 描述                                                            |
| ------------------------- | -------------- | ------------------------------------------------------------- |
| session\_filename         | str            | 存放序列化数据的文件名，默认为空                                              |
| index\_start              |                | 要运行的第一个测试用例的索引                                                |
| index\_end                |                | 要运行的最后一个测试用例的索引                                               |
| sleep\_time               |                | 每个测试用例之间等待的秒数，默认为0                                            |
| restart\_interval         |                | 在n个测试用例之后重启目标。默认情况下为0，表示禁用该选项                                 |
| **console\_gui**          | bool           | 是否使用 curses 生成类似于 Web 界面的静态控制台屏幕，默认为 False（还未在 Windows 下进行测试） |
| crash\_threshold\_request |                | 请求耗尽之前允许的最大崩溃次数，默认为12。什么是请求耗尽？                                |
| crash\_threshold\_element |                | 元素耗尽之前允许的最大崩溃次数，默认为3                                          |
| restart\_sleep\_time      |                | 当目标无法重启时等待的秒数，默认为5                                            |
| restart\_callbacks        | list of method | 在 `post_test_case_callback` 失败后调用的回调方法列表，默认为 None 。           |
| restart\_threshold        |                |                                                               |
|                           |                |                                                               |
|                           |                |                                                               |
|                           |                |                                                               |

* restart\_callbacks（list of method）：在 `post_test_case_callback` 失败后调用的回调方法列表，默认为 None 。
* restart\_threshold：丢失目标连接时的最大重试次数，默认为 None（无限次）。
* restart\_timeout：重新连接尝试的超时时间（秒），默认为 None（无限次）。
* **pre\_send\_callbacks**（list of method）：在每个模糊（测试）请求之前调用的注册方法列表，默认为 None 。
* **post\_test\_case\_callbacks**：在每个模糊测试用例之后调用的注册方法列表，默认为None。
* post\_start\_target\_callbacks：目标启动或重新启动后**进程监视器**会调用的方法，默认为 None 。
* web\_port（int 或 None）：通过 Web 浏览器监视模糊测试活动的端口。设置为 None 表示禁用 Web 应用程序，默认为 26000。
* keep\_web\_open：在会话完成后保持 Web 界面打开，默认为 True。
* fuzz\_db\_keep\_only\_n\_pass\_cases：仅在最近的n个失败或错误之前保存通过的测试用例，以减少磁盘使用量。设置为0以每个测试用例都保存（高磁盘I/O！），默认为0。
* check\_data\_received\_each\_request：如果为True，在传输每个非模糊节点后验证是否已接收到一些数据，如果没有，则注册一个失败。如果为False，则不执行此检查，默认为False。除非receive\_data\_after\_each\_request为False，否则仍会尝试接收。
* receive\_data\_after\_fuzz：如果为True，在传输模糊消息后尝试接收回复，默认为False。
* ignore\_connection\_reset：将ECONNRESET错误（"目标连接重置"）记录为"info"而不是失败，默认为False。
* ignore\_connection\_aborted：将ECONNABORTED错误记录为"info"而不是失败，默认为False。
* ignore\_connection\_issues\_when\_sending\_fuzz\_data：忽略发送模糊数据时的连接故障，默认为True。这通常是一个有用的设置，因为目标一旦消息明显无效就可能会断开连接。
* ignore\_connection\_ssl\_errors：将SSL相关错误记录为"info"而不是失败，默认为False。
* reuse\_target\_connection：如果为True，则只使用一个目标连接，而不是每个测试用例重新连接。默认为False。
* web\_address：Boofuzz 日志记录器公开的地址。默认为 `localhost`。
*   **session\_filename（str）**

    序列化持久数据的文件名，默认为None。

    **target**

    模糊（测试）会话的目标。目标必须完全初始化。默认为 None。![image-20230727152658618](file:///C:/Users/mirror4s/Desktop/rainfuzz/boofuzz-zhong-wen-wen-dang/session/images/image-20230727152658618.png?lastModify=1691983613)

    **fuzz\_loggers (list of ifuzz\_logger.IFuzzLogger)**

    日志记录器列表，用于保存测试数据和结果。默认将日志记录到 STDOUT 。

    **db\_filename**

    存储测试结果和案例信息的 SQLite 数据库文件名。默认为 `./boofuzz-results/{uniq_timestamp}.db`。

    **receive\_data\_after\_each\_request**

    如果为 True，在传输每个非模糊节点后尝试接收回复，默认为True。

### add\_node

```python
    def add_node(self, node):
        """
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        Args:
            node (pgraph.Node): Node to add to session graph
        """

        node.number = len(self.nodes)
        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self
```

### add\_target

```python
    def add_target(self, target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target (Target): Target to add to session
        """

        # pass specified target parameters to the PED-RPC server.
        target.monitors_alive()
        target.set_fuzz_data_logger(fuzz_data_logger=self._fuzz_data_logger)

        if self._callback_monitor not in target.monitors:
            target.monitors.append(self._callback_monitor)

        # add target to internal list.
        self.targets.append(target)
```

### build\_webapp\_thread

```python
    def build_webapp_thread(self, port=constants.DEFAULT_WEB_UI_PORT, address=constants.DEFAULT_WEB_UI_ADDRESS):
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
```

这段代码是一个创建和启动基于 Flask 的 Web 应用程序的线程的方法 `build_webapp_thread()`。它使用 Tornado 的 `HTTPServer` 类来监听指定的端口和地址，并将 Flask 的应用程序包装在 Tornado 的 `WSGIContainer` 中。

具体解释如下：

1. `app.session = self`：将当前对象 `self` 分配给 Flask 应用程序的 `session` 属性，以便在应用程序中访问当前会话的上下文。
2. `http_server = HTTPServer(WSGIContainer(app))`：创建一个 `HTTPServer` 实例，并将 Flask 的应用程序包装在 Tornado 的 `WSGIContainer` 中。`HTTPServer` 是 Tornado 的 HTTP 服务器，而 `WSGIContainer` 则允许在 Tornado 中运行 WSGI 应用程序。
3. `while True:`：进入一个无限循环，用于处理端口冲突的情况。
4. `http_server.listen(port, address=address)`：尝试监听指定的端口和地址。如果该端口被占用，则会引发 `socket.error` 异常。
5. `except socket.error as exc:`：捕获 `socket.error` 异常。
6. `if exc.errno != errno.EADDRINUSE:`：检查异常的错误代码是否为 `errno.EADDRINUSE`，即地址已在使用中的错误代码。
7. `port += 1`：如果端口被占用，则增加端口号，继续尝试监听新的端口。
8. `else:`：如果成功监听端口，则执行以下代码。
   * `self._fuzz_data_logger.log_info("Web interface can be found at http://%s:%d" % (address, port))`：记录日志，指示 Web 接口的地址和端口。这个日志语句将在成功启动 Web 应用程序后执行。
   * `break`：跳出循环，终止继续尝试监听端口。
9. `flask_thread = threading.Thread(target=IOLoop.instance().start)`：创建一个线程，目标为 `IOLoop.instance().start` 方法。`IOLoop.instance()` 返回 Tornado 的 I/O 循环实例，`.start` 方法用于启动 I/O 循环。
10. `flask_thread.daemon = True`：将线程标记为守护线程，以确保在主线程结束时自动退出。
11. `return flask_thread`：返回创建的线程对象。

通过调用 `build_webapp_thread()` 方法，可以创建并启动一个在后台运行的线程来托管基于 Flask 的 Web 应用程序，并监听指定的地址和端口。

### connect

建立两个请求（也可成为两个节点）之间的连接。

```python
    def connect(self, src, dst=None, callback=None):
        """
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. The session class maintains a top level node that all
        initial requests must be connected to. Example::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias. The following line is identical to the second line from the above example::

            sess.connect(s_get("HTTP"))

        Leverage callback methods to handle situations such as challenge response systems.
        A callback method must follow the message signature of :meth:`Session.example_test_case_callback`.
        Remember to include \\*\\*kwargs for forward-compatibility.

        Args:
            src (str or Request (pgrah.Node)): Source request name or request node
            dst (str or Request (pgrah.Node), optional): Destination request name or request node
            callback (def, optional): Callback function to pass received data to between node xmits. Default None.

        Returns:
            pgraph.Edge: The edge between the src and dst.
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
```

```python
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
```

```python
    def add_edge(self, graph_edge, prevent_dups=True):
        """
        Add a pgraph edge to the graph. Ensures a node exists for both the source and destination of the edge.

        @type  graph_edge:         pGRAPH Edge
        @param graph_edge:         Edge to add to graph
        @type  prevent_dups: Boolean
        @param prevent_dups: (Optional, Def=True) Flag controlling whether or not the addition of duplicate edges is ok
        """

        if prevent_dups:
            if graph_edge.id in self.edges: #  self.edges是图中边的集合
                return self

        # ensure the source and destination nodes exist.
        if self.find_node("id", graph_edge.src) is not None and self.find_node("id", graph_edge.dst) is not None:
            self.edges[graph_edge.id] = graph_edge

        return self
```

```python
 def find_node(self, attribute, value):
        """
        Find and return the node with the specified attribute / value pair.

        @type  attribute: str
        @param attribute: Attribute name we are looking for
        @type  value:     mixed
        @param value:     Value of attribute we are looking for

        @rtype:  Mixed
        @return: Node, if attribute / value pair is matched. None otherwise.
        """

        # if the attribute to search for is the id, simply return the node from the internal hash.
        if attribute == "id" and value in self.nodes:
            return self.nodes[value]

        # step through all the nodes looking for the given attribute/value pair.
        else:
            for node in listvalues(self.nodes):
                if hasattr(node, attribute):
                    if getattr(node, attribute) == value:
                        return node

        return None
```
