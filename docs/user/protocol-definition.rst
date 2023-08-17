.. _protocol-definition:

Protocol Definition
===================
对于老旧风格的协议定义，可以参看 :ref:`static protocol definition functions<static-primitives>`，此处描述的是新版本（仍处于实验阶段）的协议格式。

.. For the old school Spike-style static protocol definition format, see
 :ref:`static protocol definition functions<static-primitives>`. The non-static protocol definition
 described here is the newer (but still somewhat experimental) approach.


See the :ref:`Quickstart <quickstart>` guide for an intro to using boofuzz in general and a basic protocol definition
example.

概述
--------

**Request** 可以看作是要发送的消息，而 **Blocks** 则可视为消息内的块，
**Primitives** 则是构成 Block/Request 的元素，这些元素可以是字节、字符串、数字、checksums。

样例
-------
以下是一个 HTTP 消息的例子，演示了如何使用 Request、Block 和 primitives。

.. code-block:: python

    req = Request("HTTP-Request",children=(
        Block("Request-Line", children=(
            Group("Method", values= ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"]),
            Delim("space-1", " "),
            String("URI", "/index.html"),
            Delim("space-2", " "),
            String("HTTP-Version", "HTTP/1.1"),
            Static("CRLF", "\r\n"),
        )),
        Block("Host-Line", children=(
            String("Host-Key", "Host:"),
            Delim("space", " "),
            String("Host-Value", "example.com"),
            Static("CRLF", "\r\n"),
        )),
        Static("CRLF", "\r\n"),
    ))

下面对协议定义的具体实现展开分析。

Fuzzable
--------
.. autoclass:: boofuzz.Fuzzable


context_path
^^^^^^^^^^^^
该方法返回一个以点分割的字符串，描述了到达当前 Fuzzable 对象的上下文路径。

例如，若有一个
名为 user 的 ``Request`` 对象，并且该对象包含了一个名为 key 的 ``String`` 原语，那么对于这个
String 原语来说，其 context_path 就为 user。

.. automethod:: boofuzz.Fuzzable.context_path

qualified_name
^^^^^^^^^^^^^^
该方法与 context_path 基本类似，不过在末尾增加上了当前 Fuzzable 对象的 name。

例如，若有一个
名为 user 的 ``Request`` 对象，并且该对象包含了一个名为 key 的 ``String`` 原语，那么对于这个
String 原语来说，其 qualified_name 就为 **user.key**。


.. automethod:: boofuzz.Fuzzable.qualified_name

FuzzableBlock
--------------
.. autofunction:: boofuzz.FuzzableBlock

Request
-------
Request 是顶级容器，可含有任何 block 结构或原语 primitive。
有一些类的成员变量官方未给出明确说明，在此记录一下笔者的猜测：

- label：Request 的名称。
- stack：当前 request 对象的栈，栈中包含该 request 对象含有的块或原语。
- block_stack：open blocks 列表？
- names：一个包含多个 Fuzzable 对象的字典，以对象的 qualified_name 为键。

.. autofunction:: boofuzz.Request

Blocks
------
Block
^^^^^
.. autofunction:: boofuzz.Block

Checksum
^^^^^^^^
.. autofunction:: boofuzz.Checksum

Repeat
^^^^^^
.. autofunction:: boofuzz.Repeat

Size
^^^^
.. autofunction:: boofuzz.Size

Aligned
^^^^^^^
.. autofunction:: boofuzz.Aligned

Primitives
----------

Static
^^^^^^
Static 原语是固定的，在模糊测试时并不会发生变异。

.. autofunction:: boofuzz.Static

**示例**

.. code:: python

    Static(name="end", default_value="\r\n")

Simple
^^^^^^
.. autofunction:: boofuzz.Simple

Delim
^^^^^
.. autofunction:: boofuzz.Delim

**示例**

.. code:: python

       Delim(name="Space",default_value=" ")

Group
^^^^^
.. autofunction:: boofuzz.Group

RandomData
^^^^^^^^^^
.. autofunction:: boofuzz.RandomData

String
^^^^^^
继承自 Fuzzable，注意到 FuzzableBlock 也继承自 Fuzzable。所以 String 不是 FuzzableBlocks
的实例。


.. autofunction:: boofuzz.String

FromFile
^^^^^^^^
.. autofunction:: boofuzz.FromFile

Mirror
^^^^^^
.. autofunction:: boofuzz.Mirror

BitField
^^^^^^^^
.. autofunction:: boofuzz.BitField

Byte
^^^^
.. autofunction:: boofuzz.Byte

Bytes
^^^^^
.. autofunction:: boofuzz.Bytes

Word
^^^^
.. autofunction:: boofuzz.Word

DWord
^^^^^
.. autofunction:: boofuzz.DWord

QWord
^^^^^
.. autofunction:: boofuzz.QWord

.. _custom-blocks:

Making Your Own Block/Primitive
-------------------------------

Now I know what you're thinking: "With that many sweet primitives and blocks available, what else could I ever
conceivably need? And yet, I am urged by joy to contribute my own sweet blocks!"

To make your own block/primitive:

1. Create an object that inherits from :class:`Fuzzable <boofuzz.Fuzzable>` or :class:`FuzzableBlock <boofuzz.FuzzableBlock>`
2. Override :meth:`mutations <boofuzz.Fuzzable.mutations>` and/or :meth:`encode <boofuzz.Fuzzable.encode>`.
3. Optional: Create an accompanying static primitive function. See boofuzz's `__init__.py` file for examples.
4. ???
5. Profit!

If your block depends on references to other blocks, the way a checksum or length field depends on other parts of the
message, see the :class:`Size <boofuzz.Size>` source code for an example of how to avoid recursion issues, and Be
Careful. :)

.. autoclass:: boofuzz.Fuzzable
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: boofuzz.FuzzableBlock
    :members:
    :undoc-members:
    :show-inheritance: