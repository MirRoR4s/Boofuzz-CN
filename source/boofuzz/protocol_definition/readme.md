# [Protocol Definition](https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html#request)

## 前言

对于老旧风格的协议定义，可以参看[这里](https://boofuzz.readthedocs.io/en/stable/user/static-protocol-definition.html#static-primitives)，此处描述的是新版本的协议格式。

## 总览

Requests 是消息，Blocks 是消息内的块，Primitives 则是构成 Block/Request 的元素，这些元素可以是字节、字符串、数字、checksums。

## Fuzzable

Fuzzable 是所有 primitives 和 blocks 的父类，当创建一个新的 fuzzable 类型时，一般情况下会重写 `mutations` 和/或 `encode` 方法。

`mutations` 方法是一个生成函数，可以用来产生 mutations 即变异，通常是字节类型。

`encode` 方法是一个编码函数，通常该方法的参数来自于 `mutations` 方法或者 `default_value` 

### \_\_init\_\_(name,default_value,fuzzable)

**参数：**

- name
- default_value
- fuzzable（bool）- 用于标识是否需要对该原语进行模糊测试，默认为 True 表示需要

**返回值：**

- None

**实现思路：**

- 进行成员变量赋值
- 如果没有提供 name，那么根据类名和名称数对 name 赋值

```python
    def __init__(self, name=None, default_value=None, fuzzable=True, fuzz_values=None):

        self._fuzzable = fuzzable
        self._name = name
        self._default_value = default_value
        self._context_path = "" #  _context_path 代表什么含义？
        self._request = None #  _request 代表什么含义？
        self._halt_mutations = False
        if fuzz_values is None:
            fuzz_values = list()
        self._fuzz_values = fuzz_values

        if self._name is None:
            Fuzzable.name_counter += 1
            self._name = "{0}{1}".format(type(self).__name__, Fuzzable.name_counter)
```

### fuzzable()

装饰器方法，@property 将该方法转换为了属性。在调用的时候应该要这样 `a.fuzzable`

```python
    @property
    def fuzzable(self):
        """If False, this element should not be mutated in normal fuzzing."""
        return self._fuzzable
```

### name()

```
    @property
    def name(self):
        """Element name, should be unique for each instance.

        :rtype: str
        """
        return self._name
```

### qualified_name

```python
    @property
    def qualified_name(self):
        """Dot-delimited name that describes the request name and the path to the element within the request.

        Example: "request1.block1.block2.node1"

        """
        return ".".join(s for s in (self._context_path, self.name) if s != "")
```

### context_path()

```python
    @property
    def context_path(self):
        """Dot-delimited string that describes the path up to this element. Configured after the object is attached
        to a Request."""
        if not hasattr(self, "_context_path"):
            self._context_path = None
        return self._context_path

    @context_path.setter
    def context_path(self, x):
        self._context_path = x
```

这是一个示例代码，其中定义了一个名为 `context_path` 的属性。它使用了 `@property` 装饰器来将一个方法转换为只读的属性，并使用了 `@context_path.setter` 装饰器来定义一个设置属性值的方法。

在这个示例中，`context_path` 属性表示一个描述到达当前元素的路径的点分隔字符串。当访问 `context_path` 属性时，会调用 `context_path()` 方法获取属性的值。如果属性的值尚未设置，则返回默认值 `None`。

要设置 `context_path` 属性的值，可以使用 `context_path = x` 的形式进行赋值。在赋值时，会调用 `context_path()` 方法的 `setter`，即 `context_path(self, x)` 方法，将给定的值 `x` 赋给 `_context_path` 私有变量。

### request()

```python
    @property
    def request(self):
        """Reference to the Request to which this object is attached."""
        if not hasattr(self, "_request"):
            self._request = None
        return self._request

    @request.setter
    def request(self, x):
        self._request = x
```

### stop_mutations()

```python
    def stop_mutations(self):
        """Stop yielding mutations on the currently running :py:meth:`mutations` call.

        Used by boofuzz to stop fuzzing an element when it's already caused several failures.

        Returns:
            NoneType: None
        """
        self._halt_mutations = True
```



## Request

顶级容器，可以包含任何块 block  结构和原语 primitive。可以将 Request 看作是一个 super-block，root-block。

### \_\_init\_\_

**参数：**

- name（str，可选）- 当前 request 的名称
- children（Fuzzable，可选）- 当前 request 的孩子，默认为 None

**返回值：**

None



```python
    def __init__(self, name=None, children=None):

        FuzzableBlock.__init__(self, name=name, request=self)
        Node.__init__(self)
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

        if children is None:
            children = []
        elif isinstance(children, Fuzzable):
            children = [children]

        self._initialize_children(child_nodes=children)

    def _initialize_children(self, child_nodes, block_stack=None):

        if block_stack is None:
            block_stack = list()

        for item in child_nodes:
            item.context_path = self._generate_context_path(block_stack)
            item.request = self
            # ensure the name doesn't already exist.
            if item.qualified_name in list(self.names):
                raise exception.SullyRuntimeError("BLOCK NAME ALREADY EXISTS: %s" % item.qualified_name)
            self.names[item.qualified_name] = item

            if len(block_stack) == 0:
                self.stack.append(item)
            if isinstance(item, FuzzableBlock):
                block_stack.append(item)
                self._initialize_children(child_nodes=item.stack, block_stack=block_stack)
                block_stack.pop()
```

