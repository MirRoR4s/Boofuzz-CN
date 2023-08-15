# Session

## 前言

Session 类即会话类是 boofuzz 中的重要组成部分，主要负责发送和接收模糊测试数据包等。Session类继承自 Graph 类，所以 Session 对象相当于一个**图**。

这张图有什么属性呢？参看 Graph 类可以知道，主要有以下四种和图相关的属性：

- id（int）- 图的 id
- clusters（list）- 
- edges（dist）- 由图中的所有边构成的一个字典。键名
- nodes（dist）- 由图中的所有节点构成的一个字典。键名是节点 id，键值则是对应的节点

## 成员变量和方法

### init

会话类的构造函数。以下是各个成员变量的汇总表：

| 名称                      | 描述                                                         |
| ------------------------- | ------------------------------------------------------------ |
| session_filename（str）   | 存放序列化数据的文件名，默认为空                             |
| index\_start              | 要运行的第一个测试用例的索引                                 |
| index\_end                | 要运行的最后一个测试用例的索引                               |
| sleep\_time               | 每个测试用例之间等待的秒数，默认为0                          |
| restart\_interval         | 在n个测试用例之后重启目标。默认情况下为0，表示禁用该选项     |
| **console_gui**           | 是否使用 curses 生成类似于 Web 界面的静态控制台屏幕，默认为 False（还未在 Windows 下进行测试） |
| crash\_threshold\_request | 请求耗尽之前允许的最大崩溃次数，默认为12。什么是请求耗尽？   |
| crash\_threshold\_element | 元素耗尽之前允许的最大崩溃次数，默认为3                      |
| restart\_sleep\_time      | 当目标无法重启时等待的秒数，默认为5                          |
| restart\_callbacks        | 在 `post_test_case_callback` 失败后调用的回调方法列表，默认为 None 。 |
| restart\_threshold        |                                                              |
|                           |                                                              |
|                           |                                                              |
|                           |                                                              |

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

* **session\_filename（str）**

  序列化持久数据的文件名，默认为None。

  **target**

  模糊（测试）会话的目标。目标必须完全初始化。默认为 None。![image-20230727152658618](file:///C:/Users/mirror4s/Desktop/rainfuzz/boofuzz-zhong-wen-wen-dang/session/images/image-20230727152658618.png?lastModify=1691983613)

  **fuzz\_loggers (list of ifuzz\_logger.IFuzzLogger)**

  日志记录器列表，用于保存测试数据和结果。默认将日志记录到 STDOUT 。

  **db\_filename**

  存储测试结果和案例信息的 SQLite 数据库文件名。默认为 `./boofuzz-results/{uniq_timestamp}.db`。

  **receive\_data\_after\_each\_request**

  如果为 True，在传输每个非模糊节点后尝试接收回复，默认为True。

### add_node

顾名思义，用于添加节点。实现思路如下：

1. 获取当前节点集合长度作为新增节点的编号 number 和 id。
2. 若当前要添加的节点未在节点集合中，那么加入节点集。

**参数：**

- node（pgraph.Node）- 要加入会话图的节点

**返回值：**

- None

> [源码](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.add_node)



### [add_target](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.add_target)

向 session 中添加一个目标，可以同时对多个目标进行模糊测试。实现思路如下：

1. 1
2. 设置模糊测试数据日志记录器

参数：

- target（Target）- 要加入 session 的 Target

返回值：

- None

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

### build_webapp_thread

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
   - `self._fuzz_data_logger.log_info("Web interface can be found at http://%s:%d" % (address, port))`：记录日志，指示 Web 接口的地址和端口。这个日志语句将在成功启动 Web 应用程序后执行。

   - `break`：跳出循环，终止继续尝试监听端口。

9. `flask_thread = threading.Thread(target=IOLoop.instance().start)`：创建一个线程，目标为 `IOLoop.instance().start` 方法。`IOLoop.instance()` 返回 Tornado 的 I/O 循环实例，`.start` 方法用于启动 I/O 循环。

10. `flask_thread.daemon = True`：将线程标记为守护线程，以确保在主线程结束时自动退出。

11. `return flask_thread`：返回创建的线程对象。

通过调用 `build_webapp_thread()` 方法，可以创建并启动一个在后台运行的线程来托管基于 Flask 的 Web 应用程序，并监听指定的地址和端口。

### [connect](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.connect)

建立两个请求（即两个节点）之间的连接。

**参数：**

- src（ str 或 Request ）- 源节点名或源请求节点
- dst
- callback（def，可选）- 回调函数

**返回值：**

- pgraph.Edge

**实现思路：**

1. 若仅提供了源节点，那么将传入的源节点置为目的节点，将根节点置为真正的源节点
2. 如果传入的源节点和目标节点是字符串类型的，默认为传入的是节点名称，所以调用 `find_node` 方法寻找名称对应的节点
3. 若寻找到了源节点并且该节点不是根节点，则调用 `add_node`将其加入节点集
4. 若找到了目的节点，则将其加入节点集
5. 根据源节点和目的节点的 id，实例化 Connection 类新建一条边
6. 调用 `add_edge` 将新建的边加入 session



### example_test_case_callback

```python
    def example_test_case_callback(self, target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
        # default to doing nothing.
        self._fuzz_data_logger.log_info("No post_send callback registered.")
```

### [export_file](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.export_file)

将对象值导出到磁盘中。

参数：

- None

返回值：

- None

**实现思路：**

1. 若没有设置 `session_filename` 则直接返回
2. 构造要写入磁盘的数据，这实际上是一个字典，包含了 session_filename、total_mutant_index、sleep_time 等 session 中的成员变量
3. 新建一个名为 `session_fielname` 的文件
4. 将数据序列化并压缩后写入到文件中

### _num_mutations_recursive

num_mutation的帮助器？



```python
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
```

参数：

- this_node（request）- 当前正被模糊测试的节点，默认为空
- path（list）- 

### num_mutations

graph中的总变异数。

```python
    def num_mutations(self, max_depth=None):
        if max_depth is None or max_depth > 1:
            self.total_num_mutations = None
            return self.total_num_mutations

        return self._num_mutations_recursive()
```

参数：

- max_depth（int）- fuzzing所用的最大组合深度

返回值：

本次会话变异总数（int）





### feature_check

```python
    def feature_check(self):
        """Check all messages/features.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        for path in self._iterate_protocol_message_paths():
            self._message_check(path)
```



### [fuzz](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.fuzz)

对整个协议树进行模糊测试

```python
    def fuzz(self, name=None, max_depth=None):
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations(max_depth=max_depth)

        if name is None or name == "":
            self._main_fuzz_loop(self._generate_mutations_indefinitely(max_depth=max_depth))
        else:
            self.fuzz_by_name(name=name)
```

**参数：**

- name（str）- 一个 Request 或 test case 的名称。传入Request name就对Reuqest消息进行模糊测试，传入test case name就对test case进行模糊测试
- max_depth（int）- 最大组合深度？设为 1 表示 simple fuzzing

**返回值：**

- None

**实现思路：**

1. 根据 max_depth 调用 `num_mutations` 方法获得变异总数
2. 若 name 为空或 None，调用 `_main_fuzz_loop` ，否则调用 `fuzz_by_name` 

### fuzz_by_name

该方法通过名字对特定的测试案例或节点进行模糊测试，目前已**弃用**，使用 fuzz 方法并传入 name 参数即可。

> 源码：[boofuzz.sessions — boofuzz 0.4.1 documentation](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Session.fuzz_by_name)



参数：

- name（str）- 节点名称

返回值：

- None

### fuzz_single_case
