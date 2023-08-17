boofuzz: 网络协议模糊测试器
=====================================================


Boofuzz 源于 `Sulley`_ 模糊测试框架，但是修复了很多 Sulley 中的 bug，同时对可扩展性也作了增强。Boofuzz 的目标是万物皆可模糊测试！


起源
----

长久以来，Sulley 都是一款优秀的模糊测试器，不过其已经多年未更新，所以 Boofuzz 粉墨登场！


特点
--------

类似于 Sulley，boofuzz 也包含模糊测试器必备的一些关键特性，具体如下：

-  简单且快速的数据生成。
-  失败检测 Instrumentation。
-  失败后的目标复位。
-  记录测试数据。

Unlike Sulley, boofuzz also features:

-  Much easier install experience!
-  Support for arbitrary communications mediums.
-  Built-in support for serial fuzzing, ethernet- and IP-layer, UDP broadcast.
-  Better recording of test data -- consistent, thorough, clear.
-  Test result CSV export.
-  *Extensible* instrumentation/failure detection.
-  Far fewer bugs.

Sulley is affectionately named after the giant teal and purple creature
from Monsters Inc. due to his fuzziness. Boofuzz is likewise named after
the only creature known to have scared Sulley himself: Boo!

.. figure:: https://github.com/jtpereyda/boofuzz/raw/master/_static/boo.png
   :alt: Boo from Monsters Inc

   Boo from Monsters Inc

安装
------------
::

    pip install boofuzz


Boofuzz 实际上是一个 Python 库，我们可以利用其构建模糊测试脚本。具体安装参看
:ref:`install`。


.. toctree::
    :caption: 用户指南
    :maxdepth: 2

    user/install
    user/quickstart
    user/contributing


Public Protocol Libraries
-------------------------

The following protocol libraries are free and open source, but the implementations are not at all close to full protocol
coverage:

- `boofuzz-ftp`_
- `boofuzz-http`_

If you have an open source boofuzz protocol suite to share, please :ref:`let us know <community>`!

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

Contributions
-------------

Pull requests are welcome, as boofuzz is actively maintained (at the
time of this writing ;)). See :ref:`contributing`.

.. _community:

Community
---------

For questions that take the form of “How do I… with boofuzz?” or “I got
this error with boofuzz, why?”, consider posting your question on Stack
Overflow. Make sure to use the ``fuzzing`` tag.

If you’ve found a bug, or have an idea/suggestion/request, file an issue
here on GitHub.

For other questions, check out boofuzz on `gitter`_ or `Google Groups`_.

For updates, follow `@b00fuzz`_ on Twitter.

.. _Sulley: https://github.com/OpenRCE/sulley
.. _Google Groups: https://groups.google.com/d/forum/boofuzz
.. _gitter: https://gitter.im/jtpereyda/boofuzz
.. _@b00fuzz: https://twitter.com/b00fuzz
.. _boofuzz-ftp: https://github.com/jtpereyda/boofuzz-ftp
.. _boofuzz-http: https://github.com/jtpereyda/boofuzz-http


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`