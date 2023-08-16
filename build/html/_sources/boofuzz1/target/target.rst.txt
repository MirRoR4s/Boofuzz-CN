`Target <https://boofuzz.readthedocs.io/en/stable/source/Target.html>`__
========================================================================

前言
----

Target 是目标描述符容器。

成员变量与成员方法
------------------

`\__init_\_ <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

封装连接逻辑。

**参数：**

-  connection（ITargetConnection）- 到目标系统的连接对象
-  monitors（List[Union[IMonitor,
   `pedrpc.Client <https://boofuzz.readthedocs.io/en/stable/user/other-modules.html#boofuzz.monitors.pedrpc.Client>`__]]）-
   当前 Target 对象的监视器列表
-  monitor_alive（list）- 当监视器处于活跃状态时会调用的一个函数列表
-  repeater（\ `repeater.Repeater <https://boofuzz.readthedocs.io/en/stable/source/Target.html#boofuzz.repeater.Repeater>`__\ ）-
   发送时所用的 Repeater，默认为 None
-  procmon - 用于添加进程监视器的接口（已弃用）
-  procmon_options - 同上

**返回值：**

-  一个 Traget 对象

**实现思路：**

-  设置模糊测试数据记录器 ``_fuzz_data_logger``
-  设置目标连接对象 ``_target_connection``
-  设置最大接收字节 ``max_recv_bytes``
-  设置 ``repeater``
-  设置监视器列表 ``monitors``
-  判断是否使用了 procmon，如果有那么将 procmon 加入
   monitors，同时给出警告希望用户不要再使用 procmon 而是使用 monitors
-  设置监视器调用函数列表 ``monitor_alive``
-  设置 ``vmcontrol``\ ，vmcontrol 可能和目标的重启有关，如果 vmcontrol
   可用，那么就会恢复虚拟机快照。这个选项说明目标可能是运行在虚拟机中的

**源码：**

.. code:: python

       def __init__(
           self,
           connection,
           monitors=None, # 该目标对应的监控器列表
           monitor_alive=None,
           max_recv_bytes=10000,
           repeater=None, # 发送用到的中继器？或许类似于Burp 的同名模块
           procmon=None,
           procmon_options=None,
           **kwargs
       ):
           self._fuzz_data_logger = None # fuzz_data_logger 的含义？ 这应该就是一个日志记录器

           self._target_connection = connection
           self.max_recv_bytes = max_recv_bytes # 最大接收字节数？
           self.repeater = repeater
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
           self.vmcontrol = None # vmcontrol 应该和目标的重启有关，如果 vmcontrol 可用，那
           # 么就会恢复虚拟机快照。这个选项可能是在说明目标是运行在虚拟机中的。

           self.vmcontrol_options = {}

`close <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target.close>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

关闭到目标系统的连接。

**参数：**

-  None

**返回值：**

-  None

**实现思路：**

1. 调用目标对应套接字的 ``_target_connection.close()`` 方法

`monitors_alive() <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target.monitors_alive>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

等待监视器启动（活跃）/与 RPC 服务器建立连接。当某个 target 被添加到
session 中时，target 的每一次重启都会调用该方法。

**参数：**

-  None

**返回值：**

-  None

**实现思路：**

-  枚举当前 Target 对象的监视器列表（\ ``self.monitors``)
   判断监视器是否处于活跃状态
-  如果某监视器处于活跃状态，那么将其作为参数传入函数列表（\ ``self.monitor_alive``\ ）

`set_fuzz_data_logger(fuzz_data_logger) <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target.set_fuzz_data_logger>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

设置当前 Target 对象的 fuzz 数据记录器–用于发送和接收 fuzz 数据。

**参数：**

-  fuzz_data_logger（IFuzzLogger）- 新的 logger

**返回值：**

-  None

**实现思路：**

-  将传入参数直接赋值给成员变量 ``self._fuzz_data_logger``
