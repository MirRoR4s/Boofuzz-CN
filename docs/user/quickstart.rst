.. _quickstart:

快速开始
==========

:class:`Session <boofuzz.Session>` 对象是模糊测试会话的核心。当创建 Session 对象时，需要给其传入一个
:class:`Target <boofuzz.Target>` 对象, 而 Traget 对象本身又要接收一个 :ref:`Connection <connections>` 对象族中的对象。举个例子：

.. code-block:: python

    session = Session(
        target=Target(
            connection=TCPSocketConnection("127.0.0.1", 8021)))

Connection 对象族实现了 :class:`ITargetConnection <boofuzz.connections.ITargetConnection>` 。 Connection 对象族包括
:class:`TCPSocketConnection <boofuzz.connections.TCPSocketConnection>` 以及 UDP、SSL、
raw sockets 和 :class:`SerialConnection <boofuzz.connections.SerialConnection>` 等多个不同的套接字实现类。

创建好一个 Session 对象后，下一步需要定义协议中消息的格式。不过在那之前最好先阅读一下 RFC、tutorial 等文档熟悉你要 fuzzing 的协议的格式，
然后再利用
:ref:`块和原语（block and primitive types） <protocol-definition>` 来构造消息。

每个消息都是一个 :class:`Request <boofuzz.Request>` 对象，Request 对象的子节点定义了消息的结构。

以下是一个针对 FTP 协议的消息格式：

.. code-block:: python

    user = Request("user", children=(
        String("key", "USER"),
        Delim("space", " "),
        String("val", "anonymous"),
        Static("end", "\r\n"),
    ))

    passw = Request("pass", children=(
        String("key", "PASS"),
        Delim("space", " "),
        String("val", "james"),
        Static("end", "\r\n"),
    ))

    stor = Request("stor", children=(
        String("key", "STOR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

    retr = Request("retr", children=(
        String("key", "RETR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

完成消息的定义之后，需要使用刚刚创建好的 Session 对象将消息连接到图中。

.. Once you've defined your message(s), you will connect them into a graph using the Session object you just created:

.. code-block:: python

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)

进行模糊测试时，boofuzz 会先对 ``user`` 进行模糊测试，之后才是 ``passw``，最后是 ``stor`` 和 ``retr``。

.. When fuzzing, boofuzz will send ``user`` before fuzzing ``passw``, and ``user`` and ``passw`` before fuzzing ``stor`` or ``retr``.

在消息连接到图中之后就可以开始 fuzz 了：

.. Now you are ready to fuzz:

.. code-block:: python

    session.fuzz()

当然，以上只是一个非常基础的模糊测试器，你可以根据自己的需要对其进行修改，官方仓库中有一些 `例子 <https://github.com/jtpereyda/boofuzz/tree/master/examples>`_ 和 
`请求定义（request_definitions） <https://github.com/jtpereyda/boofuzz/tree/master/request_definitions>`_ 值得参考。

.. Note that at this point you have only a very basic fuzzer. Making it kick butt is up to you. There are some
   `examples <https://github.com/jtpereyda/boofuzz/tree/master/examples>`_ and
   `request_definitions <https://github.com/jtpereyda/boofuzz/tree/master/request_definitions>`_ in the repository that
    might help you get started.


每次运行 boofuzz 时产生的日志数据都会被保存到一个 SQLite 数据库中，该数据库位于当前工作目录下的 **boofuzz-results** 目录中。在任意时刻，你都可以通过以下命令打开数据库：

.. The log data of each run will be saved to a SQLite database located in the **boofuzz-results** directory in your
 current working directory. You can reopen the web interface on any of those databases at any time with

.. code-block:: bash

    $ boo open <run-*.db>

如果你想做一些更酷的事情，比如实现验证响应机制，那么你可以使用 :class:`Session <boofuzz.Session>` 中的 ``post_test_case_callbacks``。
为了在后续的请求中使用来自前一个响应的数据，可以参看 :class:`ProtocolSessionReference <boofuzz.ProtocolSessionReference>`。

.. To do cool stuff like checking responses, you'll want to use ``post_test_case_callbacks`` in
 :class:`Session <boofuzz.Session>`. To use data from a response in a subsequent request, see
 :class:`ProtocolSessionReference <boofuzz.ProtocolSessionReference>`.

你或许对 :ref:`custom-blocks` 也感兴趣。            

.. You may also be interested in :ref:`custom-blocks`.

记住，boofuzz 是一个纯 Python 开发的框架，所以一些更加高级的用法都需要自行定义。如果你正在做一些超级酷的事情，可以向社区 :ref:`community info <community>` 贡献你的成果。

.. Remember boofuzz is all Python, and advanced use cases often require customization.
 If you are doing crazy cool stuff, check out the :ref:`community info <community>` and consider contributing back!

Happy fuzzing, and Godspeed!

More examples
-------------
Simple FTP
^^^^^^^^^^
此处介绍一个针对 FTP 协议的模糊测试脚本，源码参看 `ftp_simple.py <https://github.com/jtpereyda/boofuzz/blob/master/examples/ftp_simple.py>`_。
为了运行该脚本，首先需要搭建一个 `FTP 服务器 <https://github.com/Siim/ftp>`_。

.. Check out the `ftp_simple.py <https://github.com/jtpereyda/boofuzz/blob/master/examples/ftp_simple.py>`_ example.
 To run it, you will need an `FTP server <https://github.com/Siim/ftp>`_.

在 FTP 服务器搭建完毕之后，在命令行下使用 ``./ftp`` 命令运行脚本即可。

注意：以上的 FTP 服务器默认情况下运行在 8021 端口，你可以根据需要自行修改。

.. Once you have compiled the FTP server, just run it with ``./ftp``.
 The server runs on port 8021 by default. Make sure to run the ftp_simple.py script against the port that the server
 is listening on.

Simple HTTP and HTTP with body
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

关于针对 HTTP 协议的模糊测试脚本可以参看 `http_simple.py <https://github.com/jtpereyda/boofuzz/blob/master/examples/http_simple.py>`_ 
和 `http_with_body.py <https://github.com/jtpereyda/boofuzz/blob/master/examples/http_with_body.py>`_。

在运行之前，首先需要搭建一个 HTTP 服务器，这可以通过使用 Python 或是其它类似于 Apache 或 NGINX 的 web 服务器来实现。

.. Good examples on how to get started with HTTP fuzzing can be found in
 `http_simple.py <https://github.com/jtpereyda/boofuzz/blob/master/examples/http_simple.py>`_
 and `http_with_body.py <https://github.com/jtpereyda/boofuzz/blob/master/examples/http_with_body.py>`_.
 Here is an example of how to execute theses scripts.
 You will need an HTTP server, you can use Python or any other webserver like Apache or NGINX for that.

.. code-block:: bash

    $ python3 -m http.server

然后根据你的服务器使用的 IP 和端口运行 ``http_simple.py`` 和 ``http_with_body.py`` 即可。

.. Then run ``http_simple.py`` or ``http_with_body.py`` against the IP and port that your server uses.