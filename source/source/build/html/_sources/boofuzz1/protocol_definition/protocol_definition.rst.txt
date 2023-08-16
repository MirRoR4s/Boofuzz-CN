`Protocol Definition <https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html#request>`__
========================================================================================================

对于老旧风格的协议定义，可以参看\ `这里 <https://boofuzz.readthedocs.io/en/stable/user/static-protocol-definition.html#static-primitives>`__\ ，此处描述的是新版本的协议格式。

概述
----

**Request** 可以看作是要发送的消息，而 **Blocks**
则可视为消息内的块，\ **Primitives** 则是构成 Block/Request
的元素，这些元素可以是字节、字符串、数字、checksums。

样例
----

以下是一个 HTTP 消息的例子，演示了如何使用 Request、Block 和
primitives。

.. code:: python

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

下面对 boofuzz 框架\ **协议定义类**\ 的实现展开分析。

`Fuzzable <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/fuzzable.html#Fuzzable>`__
-----------------------------------------------------------------------------------------------

Fuzzable 是所有 primitives 和 blocks
的父类（准确地说是父类的父类），当创建 Fuzzable
的子类时，一般情况下会重写 ``mutations()`` 和/或 ``encode()``
方法。\ ``mutations()``
方法是一个用于生成突变（通常是字节类型）的函数。而 ``encode()``
方法是一个编码函数，会对来自于 ``mutations()`` 或者 ``default_value``
的参数值进行编码。

此外，也可以重写 ``num_mutations()`` - 默认实现是调用 ``mutations()``
获取一个数字。 对于余下的方法，由 boofuzz
自行处理，所以通常不需要重写它们。

下面进行方法/函数的分析。

`\__init__() <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/fuzzable.html#Fuzzable>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**参数：**

-  name (str) -
   名称，用于后续引用。通常应提供名称，但如果没有提供，则会给出默认名称。
-  default_value (str) -
   当元素不进行模糊化时使用的值。应该代表一个有效的值。可以是静态值，也可以是\ ``ReferenceValueTestCaseSession``\ 对象。
-  fuzzable（bool）- 用于标识是否需要对该原语进行模糊化，默认为 True
-  fuzz_values () -
   自定义模糊值列表，添加到正常的突变值中。默认为\ ``None``

**返回值：**

-  None

**实现思路：**

-  进行成员变量赋值。

   .. code:: python

          def __init__(self, name=None, default_value=None, fuzzable=True, fuzz_values=None):

              self._fuzzable = fuzzable
              self._name = name
              self._default_value = default_value
              self._context_path = "" #  （上下文路径）初始化为空字符串
              self._request = None #  （请求）初始化为None
              self._halt_mutations = False # （停止突变）初始化为 False，表示不停止突变。

-  模糊值列表如果未提供，则初始化为空列表。如果未指定名称(``name`` is
   None)，则会使用默认名称。默认名称是基于类名和一个计数器生成的。

   .. code:: python

              if fuzz_values is None:
                  fuzz_values = list()
              self._fuzz_values = fuzz_values

              if self._name is None:
                  Fuzzable.name_counter += 1
                  self._name = "{0}{1}".format(type(self).__name__, Fuzzable.name_counter)

   ..

      \_context_path
      是一个以点号作为分隔符的字符串，描述了到达当前元素的路径。

`encode() <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/fuzzable.html#Fuzzable.encode>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

该方法用于将 value 编码成一个字节串。

**参数：**

-  value (str) - 要编码的值，类型应和由 ``mutations()``
   方法产生的变量相匹配。
-  mutation_context (MutationContext) - 当前变异的上下文

**返回值：**

-  编码后/序列化后的值 (bytes)

**实现：**

-  具体实现由子类负责

..

   fuzzable 属性用于表明元素是否要进行模糊测试，如果为 False 则不需要。

`get_mutations() <https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/fuzzable.html#Fuzzable.get_mutations>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _fuzzable-1:

fuzzable()
~~~~~~~~~~

装饰器方法，@property 将该方法转换为了属性。比如 a 是一个 Fuzzable
对象，那么可以通过 ``a.fuzzable`` 获取到 \_fuzzable 属性。

   装饰器方法允许我们像调用成员变量一样去调用成员方法。

.. code:: python

       @property
       def fuzzable(self):
           """If False, this element should not be mutated in normal fuzzing."""
           return self._fuzzable

name()
~~~~~~

返回元素名称，该名称对于每个实例来说应该是唯一的。

.. code:: python

       @property
       def name(self):
           """Element name, should be unique for each instance.

           :rtype: str
           """
           return self._name

qualified_name()
~~~~~~~~~~~~~~~~

一个装饰器函数，会返回一个描述请求名称和请求内元素路径的以点号作为分隔符的字符串。

字符串的值由 ``_context_path`` 和 ``name``
组成，通过点号连接起来。例如，如果 ``_context_path``
为“request1.block1.block2”，\ ``name``
为“node1”，则返回的字符串将是“request1.block1.block2.node1”。

.. code:: python

       @property
       def qualified_name(self):
           return ".".join(s for s in (self._context_path, self.name) if s != "")

context_path()
~~~~~~~~~~~~~~

context_path 是一个装饰器函数，由 getter 和 setter
方法组成，用于描述到达当前元素的路径的点分隔字符串。

**实现思路：**

-  在 getter
   方法中，首先检查是否存在\ ``_context_path``\ 属性。如果不存在，则将其设置为\ ``None``\ 。然后返回
   ``_context_path`` 的值。

   .. code:: python

         @property
          def context_path(self):
              if not hasattr(self, "_context_path"):
                  self._context_path = None
              return self._context_path

-  在 setter 方法中，将传入的值赋给 ``_context_path`` 属性。

   .. code:: python

         @context_path.setter
          def context_path(self, x):
              self._context_path = x

request
~~~~~~~

.. code:: python

       @property
       def request(self):
           """Reference to the Request to which this object is attached."""
           if not hasattr(self, "_request"):
               self._request = None
           return self._request

       @request.setter
       def request(self, x):
           self._request = x

stop_mutations()
~~~~~~~~~~~~~~~~

该方法用于停止当前运行的\ ``mutations``\ 调用中的突变生成。在当一个元素已经导致了多个失败时，boofuzz使用这个方法来停止对该元素进行模糊化。

方法内部将属性\ ``_halt_mutations``\ 设置为\ ``True``\ ，表示停止突变生成。

该方法不返回任何值，返回类型为\ ``None``\ 。

通过调用\ ``stop_mutations()``\ 方法，可以在需要的时候停止对元素进行模糊化。

.. code:: python

       def stop_mutations(self):
           """Stop yielding mutations on the currently running :py:meth:`mutations` call.

           Used by boofuzz to stop fuzzing an element when it's already caused several failures.

           Returns:
               NoneType: None
           """
           self._halt_mutations = True

FuzzableBlock
-------------

待定。

.. _request-1:

Request
-------

顶级容器，可以包含任何 block structure 和 primitive。如前所述，Request
实际上代表着要发送的消息，该消息可由许多 blocks 组成，所以可以将 Request
看作是一个超级块、根块等等。

Request 对应着 Request 类，该类继承自 ``FuzzableBlock`` 和 ``Node``
，下面对 Request 类的具体实现展开分析与说明。

.. _init__-1:

\__init_\_
~~~~~~~~~~

**参数：**

-  name（str，可选）- 当前 request 的名称
-  children（Fuzzable，可选）- 当前 request 的子节点，默认为 None

**返回值：**

-  一个 Request 对象

**实现思路：**

-  调用两个父类的构造函数进行初始化，注意到这里并没有用 super 实例化
   Request 对象。

   .. code:: python

          def __init__(self, name=None, children=None):

              FuzzableBlock.__init__(self, name=name, request=self)
              Node.__init__(self)

-  成员变量赋值，label 是节点标签，stack 是请求栈（request
   stack），block_stack 是由 open blocks 组成的列表。callbacks
   是一个字典，通过使用\ ``self.callbacks[key]``\ ，可以使用\ ``key``\ 来访问\ ``self.callbacks``\ 中对应的值，如果该键不存在，则会返回一个空列表。

   .. code:: python

              self.label = name  # node label for graph rendering.
              self.stack = []  # the request stack.
              self.block_stack = []  # list of open blocks, -1 is last open block.
              self.callbacks = collections.defaultdict(list)
              self.names = {name: self}  # dictionary of directly accessible primitives.
              self._rendered = b""  # rendered block structure.

              self._mutant_index = 0  # current mutation index.
              #当前的变异索引是什么？

              self._element_mutant_index = None  # index of current mutant element within self.stack

              self.mutant = None  # current primitive being mutated.

-  如果子节点不是 None，则对子节点进行初始化

   .. code:: python

              if children is None:
                  children = []
              elif isinstance(children, Fuzzable):
                  children = [children]

              self._initialize_children(child_nodes=children)

\_initialize_children
~~~~~~~~~~~~~~~~~~~~~
