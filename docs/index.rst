boofuzz: 网络协议模糊测试器
=====================================================
前言
^^^^
Boofuzz 是 Sulley 框架的继承者，修复了很多 Sulley 中的 bug，并对可扩展性做了增强，可以看作是 Sulley 的升级版。

.. note::
    
    Boofuzz 的宗旨是万物皆可模糊测试！



起源
----

长久以来，Sulley 都是一款优秀的模糊测试器，不过其已经多年未更新，所以 Boofuzz 粉墨登场！


特点
--------

类似于 Sulley，boofuzz 也包含模糊测试器必备的一些关键特性，具体如下：

-  简单且快速的数据生成。
-  失败检测。
-  失败后的目标复位。
-  记录测试数据。

但 boofuzz 不同于 Sulley 独有的特点如下：

-  更加易于安装！
 .. Much easier install experience!
-  支持任意的通信介质。
.. Support for arbitrary communications mediums.
-  内置支持对一系列协议的模糊测试，比如以太网协议、IP层协议等。
.. Built-in support for serial fuzzing, ethernet- and IP-layer, UDP broadcast.
-  能够更好地记录测试数据 -- 一致、彻底、清晰。
.. Better recording of test data -- consistent, thorough, clear.
-  测试结果 CVS 导出。
.. Test result CSV export.
-  可扩展指令/失败监测 
.. *Extensible* instrumentation/failure detection.
-  bugs 更少。
.. Far fewer bugs.



安装
------------
:: 

    pip install boofuzz


Boofuzz 实际上是一个 Python 库，我们可以利用其构建模糊测试脚本。具体安装参看
:ref:`install`。


.. toctree::
    :caption: 用户指南
    :maxdepth: 2

    user/foreword
    user/install
    user/quickstart
    user/contributing




.. toctree::
    :caption: API 文档
    :maxdepth: 2

    source/Session
    source/Target
    user/connections
    user/monitors
    user/logging
    user/protocol-definition
    user/static-protocol-definition
    user/other-modules

.. toctree::
    :maxdepth: 1

    user/changelog

.. toctree::
    :caption: 学习记录
    :maxdepth: 1

    examples/official
    examples/s7comm
    user/work




索引
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`