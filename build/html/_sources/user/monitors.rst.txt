.. _monitors:

========
Monitors
========
Monitors 就是监视目标特定行为的组件，一般称之为监视器。监视器可以是被动的，也可以是主动的。
被动的意思是仅对目标进行观察并提供一些数据，而主动的意思则是表明监视器的行为更加的积极，比如直接和目标进行交互等。
更进一步地，有些监视器甚至具有启动、停止、重启目标的能力。

.. Monitors are components that monitor the target for specific behaviour. A
.. monitor can be passive and just observe and provide data or behave more actively,
.. interacting directly with the target. Some monitors also have the capability to
.. start, stop and restart targets.

监测目标的崩溃或异常行为可能是一件复杂的事情，主要取决于在目标系统上有哪些可用的工具。
比如对嵌入式设备来说，在其上通常没有现成的能够监测崩溃/异常的工具。

Boofuzz 主要提供了三种监视器实现类：

.. Detecting a crash or misbehaviour of your target can be a complex, non-straight
.. forward process depending on the tools you have available on your targets host;
.. this holds true especially for embedded devices. Boofuzz provides three main
.. monitor implementations:

- :class:`ProcessMonitor <boofuzz.monitors.ProcessMonitor>`：从 Windows 和 Unix 进程中收集调试信息的监视器类。该类也可以重启目标进程以及监测段错误。

- :class:`NetworkMonitor <boofuzz.monitors.NetworkMonitor>`：通过 PCAP 被动地捕获网络流量并将其写入测试用例日志中的监视器类。

- :class:`CallbackMonitor <boofuzz.monitors.CallbackMonitor>`：用于实现回调函数的监视器类，可以传递给 Session 类。

.. - :class:`ProcessMonitor <boofuzz.monitors.ProcessMonitor>`, a Monitor that collects debug info from process on Windows
..   and Unix. It also can restart the target process and detect segfaults.
.. - :class:`NetworkMonitor <boofuzz.monitors.NetworkMonitor>`, a Monitor that passively captures network traffic via PCAP
..   and attaches it to the testcase log.
.. - :class:`CallbackMonitor <boofuzz.monitors.CallbackMonitor>`, which is used to implement the callbacks that can be
..   supplied to the Session class.

Monitor Interface (BaseMonitor)
===============================

.. autoclass:: boofuzz.monitors.BaseMonitor
   :members:
   :undoc-members:
   :show-inheritance:

ProcessMonitor
==============

The process monitor consists of two parts; the ``ProcessMonitor`` class that implements
``BaseMonitor`` and a second module that is to be run on the host of your target.

.. autoclass:: boofuzz.monitors.ProcessMonitor
   :members:
   :undoc-members:

NetworkMonitor
==============

The network monitor consists of two parts; the ``NetworkMonitor`` class that implements
``BaseMonitor`` and a second module that is to be run on a host that can monitor the traffic.

.. autoclass:: boofuzz.monitors.NetworkMonitor
   :members:
   :undoc-members:

CallbackMonitor
===============

.. autoclass:: boofuzz.monitors.CallbackMonitor
   :members:
   :undoc-members: