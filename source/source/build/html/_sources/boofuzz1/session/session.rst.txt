Session
=======

前言
----

Session 类即会话类是 boofuzz
中的重要组成部分，主要负责发送和接收模糊测试数据包等。Session类继承自
Graph 类，所以 Session 对象相当于一个\ **图**\ 。

这张图有什么属性呢？参看 Graph
类可以知道，主要有以下四种和图相关的属性：

-  id（int）- 图的 id
-  clusters（list）-
-  edges（dist）- 由图中的所有边构成的一个字典。
-  nodes（dist）- 由图中的所有节点构成的一个字典。键名是节点
   id，键值则是对应的节点

成员变量和方法
--------------

`\__init_\_ <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**参数：**

+----------------------------------+-----------------------------------+
| 名称                             | 描述                              |
+==================================+===================================+
| session_filename（str）          | 存放序列化数据的文件名，默认为    |
|                                  | None                              |
+----------------------------------+-----------------------------------+
| index_start                      | 要运行的第一个测试用例的索引      |
+----------------------------------+-----------------------------------+
| index_end                        | 要运行的最后一个测试用例的索引    |
+----------------------------------+-----------------------------------+
| sleep_time                       | 每                                |
|                                  | 个测试用例之间等待的秒数，默认为  |
|                                  | 0                                 |
+----------------------------------+-----------------------------------+
| restart_interval                 | 在 n                              |
|                                  | 个测试用例之后重启目              |
|                                  | 标。默认情况下为0，表示禁用该选项 |
+----------------------------------+-----------------------------------+
| console_gui                      | 是否使用 curses 在 web            |
|                                  | 端生成一个静态控制台，默认为      |
|                                  | False（还未在 Windows             |
|                                  | 下进行测试）                      |
+----------------------------------+-----------------------------------+
| crash_threshold_request          | 请求耗                            |
|                                  | 尽之前允许的最大崩溃次数，默认为  |
|                                  | 12。什么是请求耗尽？              |
+----------------------------------+-----------------------------------+
| crash_threshold_element          | 元素耗                            |
|                                  | 尽之前允许的最大崩溃次数，默认为  |
|                                  | 3                                 |
+----------------------------------+-----------------------------------+
| restart_sleep_time               | 当                                |
|                                  | 目标无法重启时等待的秒数，默认为5 |
+----------------------------------+-----------------------------------+
| restart_callbacks                | 在 ``post_test_case_callback``    |
|                                  | 失败后调用的回调方法列表，默认为  |
|                                  | None                              |
+----------------------------------+-----------------------------------+
| restart_threshold                | 丢失                              |
|                                  | 目标连接时的最大重试次数，默认为  |
|                                  | None（无限次）                    |
+----------------------------------+-----------------------------------+
| restart_timeout                  | 重新                              |
|                                  | 连接尝试的超时时间（秒），默认为  |
|                                  | None（无限次）                    |
+----------------------------------+-----------------------------------+
| pre_send_callbacks               | 在每个模糊（测试）请              |
|                                  | 求之前调用的注册方法列表，默认为  |
|                                  | None                              |
+----------------------------------+-----------------------------------+
| post_test_case_callbacks         | 在每个模糊测试用例之              |
|                                  | 后调用的注册方法列表，默认为None  |
+----------------------------------+-----------------------------------+
| post_start_target_callbacks      | 目标启动或重新启动后\ **进        |
|                                  | 程监视器**\ 会调用的方法，默认为  |
|                                  | None 。                           |
+----------------------------------+-----------------------------------+
| web_port                         | 通过 Web                          |
|                                  | 浏览                              |
|                                  | 器监视模糊测试活动的端口。设置为  |
|                                  | None 表示禁用 Web                 |
|                                  | 应用程序，默认为 26000            |
+----------------------------------+-----------------------------------+
| keep_web_open                    | 在会话完成后保持 Web              |
|                                  | 界面打开，默认为 True             |
+----------------------------------+-----------------------------------+
| fuzz_loggers（list）             | 日志记录器列表，用于保存          |
|                                  | 测试数据和结果。默认将日志记录到  |
|                                  | STDOUT 。                         |
+----------------------------------+-----------------------------------+
| fuzz_db_keep_only_n_pass_cases   | 仅在最近的n个失败或错             |
|                                  | 误之前保存通过的测试用例，以减少  |
|                                  | 磁盘使用量。设置为0以每个测试用例 |
|                                  | 都保存（高磁盘I/O！），默认为0。  |
+----------------------------------+-----------------------------------+
| receive_data_after_each_request  | 如果为                            |
|                                  | True，在传输每个非模糊            |
|                                  | 节点后尝试接收回复，默认为True。  |
+----------------------------------+-----------------------------------+
| receive_data_after_fuzz（bool）  | 如果该变量为真，那么在传输完一个  |
|                                  | fuzzed 消息后，Session            |
|                                  | 会尝试接收一个响应                |
+----------------------------------+-----------------------------------+
| ignore_connection_reset（bool）  | 将 ECONNREST                      |
|                                  | 错误（目标连接复位）记录为 “info” |
|                                  | 而非 failures                     |
+----------------------------------+-----------------------------------+
| i                                | 将ECONNABORTED错误记录            |
| gnore_connection_aborted（bool） | 为“info”而不是失败，默认为False。 |
+----------------------------------+-----------------------------------+
| **ignore_connection              | 忽略                              |
| _issues_when_sending_fuzz_data** | 发送模糊数据时的连接故障，默认为  |
|                                  | True。这                          |
|                                  | 通常是一个有用的设置，因为目标一  |
|                                  | 旦消息明显无效就可能会断开连接。  |
+----------------------------------+-----------------------------------+
| ignore_connection_ssl_errors     | 将SSL相关错误记录                 |
|                                  | 为“info”而不是失败，默认为False。 |
+----------------------------------+-----------------------------------+
| reuse_target_connection          | 如果为                            |
|                                  | True，则只使用一个目标连接，而    |
|                                  | 不是每个测试用例重新连接。默认为  |
|                                  | False。                           |
+----------------------------------+-----------------------------------+
| **target**                       | 模糊（测试）会话的                |
|                                  | 目标。目标必须完全初始化。默认为  |
|                                  | None。                            |
+----------------------------------+-----------------------------------+
| **db_filename**                  | 存储测试结果和案例信息的 SQLite   |
|                                  | 数据库文件名。默认为              |
|                                  | ``./boofuzz-                      |
|                                  | results/{uniq_timestamp}.db``\ 。 |
+----------------------------------+-----------------------------------+
| targets                          | 一个包含着多个 Target 对象的列表  |
+----------------------------------+-----------------------------------+
| \_callback_monitor               | 一个回调监视器列表，具体参看源码  |
+----------------------------------+-----------------------------------+

**返回值：**

-  一个 Session 对象

**实现思路：**

-  设置下列成员变量：

.. code:: python

           self._ignore_connection_reset = ignore_connection_reset
           self._ignore_connection_aborted = ignore_connection_aborted
           self._ignore_connection_issues_when_sending_fuzz_data = ignore_connection_issues_when_sending_fuzz_data
           self._reuse_target_connection = reuse_target_connection
           self._ignore_connection_ssl_errors = ignore_connection_ssl_errors

-  调用父类构造函数：

.. code:: python

   super(Session, self).__init__()

.. code:: python

       def __init__(self, graph_id=None):
           self.id = graph_id
           self.clusters = []
           self.edges = {}
           self.nodes = {}

-  设置下列成员变量：

.. code:: python

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

-  如果日志记录器是 None，将其初始化为一个空的列表。此时如果要在 web
   端生成一个控制台并且操作系统不是 Windows，

.. code:: python

           if fuzz_loggers is None: # 当没有设置记录器的时候，默认输出到标准输出。
               fuzz_loggers = []
               if self.console_gui and os.name != "nt":
                   fuzz_loggers.append(fuzz_logger_curses.FuzzLoggerCurses(web_port=self.web_port))
                   self._keep_web_open = False
               else:
                   fuzz_loggers = [fuzz_logger_text.FuzzLoggerText()]

`add_node(node) <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.add_node>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**参数：**

-  node（pgraph.Node）- 要加入会话图的节点

**返回值：**

-  None

**实现思路：**

-  获取当前节点集合长度作为新增节点的编号 number 和 id。
-  若当前要添加的节点未在节点集合中，那么加入节点集。

`add_target <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.add_target>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

向 session 中添加一个目标，可以同时对多个目标进行模糊测试

**参数：**

-  target（Target）- 要加入 session 的 Target

**返回值：**

-  None

**实现思路：**

-  等待监视器启动（活跃）/与 RPC 服务器建立连接
-  设置模糊测试数据日志记录器
-  如果 ``_callback_monitors`` 不在 target.monitors 中，那么就添加进去
-  将 target 添入 targets

build_webapp_thread
~~~~~~~~~~~~~~~~~~~

.. code:: python

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

这段代码是一个创建和启动基于 Flask 的 Web 应用程序的线程的方法
``build_webapp_thread()``\ 。它使用 Tornado 的 ``HTTPServer``
类来监听指定的端口和地址，并将 Flask 的应用程序包装在 Tornado 的
``WSGIContainer`` 中。

具体解释如下：

1.  ``app.session = self``\ ：将当前对象 ``self`` 分配给 Flask
    应用程序的 ``session`` 属性，以便在应用程序中访问当前会话的上下文。

2.  ``http_server = HTTPServer(WSGIContainer(app))``\ ：创建一个
    ``HTTPServer`` 实例，并将 Flask 的应用程序包装在 Tornado 的
    ``WSGIContainer`` 中。\ ``HTTPServer`` 是 Tornado 的 HTTP 服务器，而
    ``WSGIContainer`` 则允许在 Tornado 中运行 WSGI 应用程序。

3.  ``while True:``\ ：进入一个无限循环，用于处理端口冲突的情况。

4.  ``http_server.listen(port, address=address)``\ ：尝试监听指定的端口和地址。如果该端口被占用，则会引发
    ``socket.error`` 异常。

5.  ``except socket.error as exc:``\ ：捕获 ``socket.error`` 异常。

6.  ``if exc.errno != errno.EADDRINUSE:``\ ：检查异常的错误代码是否为
    ``errno.EADDRINUSE``\ ，即地址已在使用中的错误代码。

7.  ``port += 1``\ ：如果端口被占用，则增加端口号，继续尝试监听新的端口。

8.  ``else:``\ ：如果成功监听端口，则执行以下代码。

    -  ``self._fuzz_data_logger.log_info("Web interface can be found at http://%s:%d" % (address, port))``\ ：记录日志，指示
       Web 接口的地址和端口。这个日志语句将在成功启动 Web
       应用程序后执行。

    -  ``break``\ ：跳出循环，终止继续尝试监听端口。

9.  ``flask_thread = threading.Thread(target=IOLoop.instance().start)``\ ：创建一个线程，目标为
    ``IOLoop.instance().start`` 方法。\ ``IOLoop.instance()`` 返回
    Tornado 的 I/O 循环实例，\ ``.start`` 方法用于启动 I/O 循环。

10. ``flask_thread.daemon = True``\ ：将线程标记为守护线程，以确保在主线程结束时自动退出。

11. ``return flask_thread``\ ：返回创建的线程对象。

通过调用 ``build_webapp_thread()``
方法，可以创建并启动一个在后台运行的线程来托管基于 Flask 的 Web
应用程序，并监听指定的地址和端口。

`connect <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.connect>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

建立两个请求（即两个节点）之间的连接。

**参数：**

-  src（ str 或 Request ）- 源节点名或源请求节点
-  dst
-  callback（def，可选）- 回调函数

**返回值：**

-  pgraph.Edge

**实现思路：**

-  若仅提供了源节点，那么将传入的源节点置为目的节点，将根节点置为真正的源节点

   .. code:: python

              if dst is None:
                  dst = src
                  src = self.root

-  如果传入的源节点和目标节点是字符串类型的，那么默认传入的是节点名称，调用
   ``find_node`` 方法寻找名称对应的节点

   ::

              if isinstance(src, six.string_types):
                  src = self.find_node("name", src)

1. 若寻找到了源节点并且该节点不是根节点，则调用
   ``add_node``\ 将其加入节点集
2. 若找到了目的节点，则将其加入节点集
3. 根据源节点和目的节点的 id，实例化 Connection 类新建一条边
4. 调用 ``add_edge`` 将新建的边加入 session

example_test_case_callback
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

       def example_test_case_callback(self, target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
           # default to doing nothing.
           self._fuzz_data_logger.log_info("No post_send callback registered.")

`export_file <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.export_file>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

将对象值导出到磁盘中。

参数：

-  None

返回值：

-  None

**实现思路：**

1. 若没有设置 ``session_filename`` 则直接返回
2. 构造要写入磁盘的数据，实际上是一个字典，包含了
   session_filename、total_mutant_index、sleep_time 等 session
   中的成员变量
3. 新建一个名为 ``session_fielname`` 的文件
4. 将数据序列化并压缩后写入到文件中

\_num_mutations_recursive
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

       def _num_mutations_recursive(self, this_node=None, path=None):
           if this_node is None:
               this_node = self.root
               self.total_num_mutations = 0

           if path is None:
               path = []

           for edge in self.edges_from(this_node.id): #  edges_from寻找所有以this_node.id为起点的边，并以一个列表的形式返回
               next_node = self.nodes[edge.dst]
               self.total_num_mutations += next_node.get_num_mutations()

               if edge.src != self.root.id:
                   path.append(edge)

               self._num_mutations_recursive(next_node, path)

           # finished with the last node on the path, pop it off the path stack.
           if path:
               path.pop()

           return self.total_num_mutations

参数：

-  this_node（request）- 当前正被模糊测试的节点，默认为空
-  path（list）-

num_mutations
~~~~~~~~~~~~~

graph中的总变异数。

.. code:: python

       def num_mutations(self, max_depth=None):
           if max_depth is None or max_depth > 1:
               self.total_num_mutations = None
               return self.total_num_mutations

           return self._num_mutations_recursive()

参数：

-  max_depth（int）- fuzzing所用的最大组合深度

返回值：

本次会话变异总数（int）

feature_check
~~~~~~~~~~~~~

.. code:: python

       def feature_check(self):
           """Check all messages/features.

           Returns:
               None
           """
           self.total_mutant_index = 0
           self.total_num_mutations = self.num_mutations()

           for path in self._iterate_protocol_message_paths():
               self._message_check(path)

`fuzz <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.fuzz>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

对整个协议树进行模糊测试

.. code:: python

       def fuzz(self, name=None, max_depth=None):
           self.total_mutant_index = 0
           self.total_num_mutations = self.num_mutations(max_depth=max_depth)

           if name is None or name == "":
               self._main_fuzz_loop(self._generate_mutations_indefinitely(max_depth=max_depth))
           else:
               self.fuzz_by_name(name=name)

**参数：**

-  name（str）- 一个 Request 或 test case 的名称。传入Request
   name就对Reuqest消息进行模糊测试，传入test case name就对test
   case进行模糊测试
-  max_depth（int）- 最大组合深度？设为 1 表示 simple fuzzing

**返回值：**

-  None

**实现思路：**

1. 根据 max_depth 调用 ``num_mutations`` 方法获得变异总数
2. 若 name 为空或 None，调用 ``_main_fuzz_loop`` ，否则调用
   ``fuzz_by_name``

`fuzz_by_name <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.fuzz_by_name>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

该方法通过名字对特定的测试案例或节点进行模糊测试，目前已\ **弃用**\ ，使用
fuzz 方法并传入 name 参数即可。

参数：

-  name（str）- 节点名称

返回值：

-  None

fuzz_single_case
~~~~~~~~~~~~~~~~
