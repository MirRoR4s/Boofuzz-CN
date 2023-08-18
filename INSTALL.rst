安装 boofuzz
==================

前提
-------------
Boofuzz 要求 Python 版本 >= 3.7，建议使用 pip 安装。此外，在安装 boofuzz 之前需要先安装以下的包：
 
.. Boofuzz requires Python ≥ 3.7. Recommended installation requires ``pip``. As a base requirement, the following packages
 are needed:

Ubuntu/Debian
  ``sudo apt-get install python3-pip python3-venv build-essential``
OpenSuse
  ``sudo zypper install python3-devel gcc``
CentOS
  ``sudo yum install python3-devel gcc``

安装
-------
强烈建议将 boofuzz 设置在一个 `虚拟环境
(venv) <https://docs.python.org/3/tutorial/venv.html>`_ 中。首先，创建一个目录，该目录会作为 boofuzz 的安装目录。

.. It is strongly recommended to set up boofuzz in a `virtual environment
 (venv) <https://docs.python.org/3/tutorial/venv.html>`_. First, create a directory that will hold our boofuzz install:

.. code-block:: bash

    $ mkdir boofuzz && cd boofuzz
    $ python3 -m venv env

以上命令会在当前目录中创建一个新的虚拟环境。注意到在虚拟环境中的 Python 版本是固定的，并且可在创建时选择。
为什么要使用虚拟环境？不同于全局的安装，在虚拟环境中，``python`` 是虚拟环境的 Python 版本的别名。

.. This creates a new virtual environment env in the current folder. Note that the
 Python version in a virtual environment is fixed and chosen at its creation.
 Unlike global installs, within a virtual environment ``python`` is aliased to
 the Python version of the virtual environment.

紧接着，激活虚拟环境：

.. Next, activate the virtual environment:

.. code-block:: bash

    $ source env/bin/activate

如果你是在 Windows 下：

.. Or, if you are on Windows:

.. code-block:: batch

    > env\Scripts\activate.bat

确保你的 ``pip`` 和 ``setuptools`` 是最新的版本：

.. Ensure you have the latest version of both ``pip`` and ``setuptools``:

.. code-block:: bash

    (env) $ pip install -U pip setuptools

最后，安装 boofuzz：

.. Finally, install boofuzz:

.. code-block:: bash

    (env) $ pip install boofuzz

为了运行以及测试你的模糊测试脚本，确保始终激活虚拟环境。

.. To run and test your fuzzing scripts, make sure to always activate the virtual
 environment beforehand.

源码安装
-----------


1. Like above, it is recommended to set up a virtual environment. Depending on your
   concrete setup, this is largely equivalent to the steps outlined above. Make sure
   to upgrade ``setuptools`` and ``pip``.
2. Download the source code. You can either grab a zip from https://github.com/jtpereyda/boofuzz
   or directly clone it with git:

   .. code-block:: bash

      $ git clone https://github.com/jtpereyda/boofuzz.git

3. Install. Run ``pip`` from within the boofuzz directory after activating the virtual
   environment:

   .. code-block:: bash

       $ pip install .

Tips:

-  Use the ``-e`` option for developer mode, which allows changes to be
   seen automatically without reinstalling:

   .. code-block:: bash

       $ pip install -e .

-  To install developer tools (unit test dependencies, test runners, etc.) as well:

   .. code-block:: bash

       $ pip install -e .[dev]

-  If you’re behind a proxy:

   .. code-block:: bash

       $ set HTTPS_PROXY=http://your.proxy.com:port

- If you're planning on developing boofuzz itself, you can save a directory and
  create your virtual environment after you've cloned the source code (so ``env/``
  is within the main boofuzz directory).

Extras
------

process\_monitor.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

进程监视器（process monitor）是一个工具，用于监测 Windows 或 Linux 中应用程序的崩溃和重启。虽然 boofuzz 通常来说并不和目标运行在同一台机器上，但是进程监视器
必须运行在目标上。

.. The process monitor is a tool for detecting crashes and restarting an application on Windows or Linux. While boofuzz
 typically runs on a different machine than the target, the process monitor must run on the target machine itself.

network\_monitor.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

网络监视器（network monitor）是 Sulley's 的主要工具之一，用于记录测试数据。不过在 boofuzz 中使用日志机制来替代了该功能。然而，
一些人仍然更加喜爱 PCAP 方法。

.. The network monitor was Sulley’s primary tool for recording test data,
 and has been replaced with boofuzz’s logging mechanisms.
 However, some people still prefer the PCAP approach.

.. note::
    网络监视器需要安装 Pcapy 和 Impacket，但是 boofuzz 中并不会自动安装这两个包，所以你需要使用 ``pip install pcapy impacket`` 
    手动地安装它们。
    
    如果运行时发生了错误，可在 `project page <https://github.com/helpsystems/pcapy>`_ 检查你的 Pcapy 是否符合要求。
    
    .. The network monitor requires Pcapy and Impacket, which will not be automatically installed with boofuzz. You can
     manually install them with ``pip install pcapy impacket``.

     If you run into errors, check out the Pcapy requirements on the `project page <https://github.com/helpsystems/pcapy>`_.

.. _help site: http://www.howtogeek.com/197947/how-to-install-python-on-windows/
.. _releases page: https://github.com/jtpereyda/boofuzz/releases
.. _`https://github.com/jtpereyda/boofuzz`: https://github.com/jtpereyda/boofuzz
