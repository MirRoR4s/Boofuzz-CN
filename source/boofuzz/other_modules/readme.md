# [Other Modules](https://boofuzz.readthedocs.io/en/stable/user/other-modules.html#module-boofuzz.helpers)

## Test Case Session Reference

## Helpers

在 Helpers 中有许多的帮助函数。

### 分析

#### get_boofuzz_version(boofuzz_class)

该函数的作用是解析 boofuzz 库中的 `__init__.py` 文件，从中提取版本号，并以字符串形式返回。

**参数：**

- boofuzz_class (class) -  boofuzz 类

**返回值：**

- Boofuzz version (str) - 字符串形式的 Boofuzz 版本

**实现思路：**

1. 首先，通过参数`boofuzz_class`获取 boofuzz 类所在的目录路径。

   ```python
   path = os.path.dirname(boofuzz_class.__file__)
   ```

   

2. 然后，打开`__init__.py`文件，并按行遍历其中的内容。对于每一行，通过查找`__version__ = `来判断是否找到了版本号的定义行。如果找到了版本号的定义行，则通过正则表达式提取出版本号，并在前面加上前缀"v"，最后将其作为结果返回。如果在`__init__.py`文件中没有找到版本号的定义行，则返回默认的版本号字符串"v-.-.-"。

   ```python
       path = os.path.dirname(boofuzz_class.__file__)
       with open(os.path.join(path, "__init__.py")) as search:
           for line in search:
               if line.find("__version__ = ") != -1:
                   return "v" + re.search(r'"(.*?)"', line).group(1)  # pytype: disable=attribute-error
       return "v-.-.-"
   ```

   

#### hex_to_hexstr(input_bytes)

该函数用于将字节数据转换为 ASCII 编码的十六进制字节字符串，然后附加一个 UTF-8 解码的字符串。

**参数：**

- input_bytes (bytes) - 任意的字节

**返回值：**

- 可打印的字符串 (str)

**实现思路：**

1. 函数接收一个参数`input_bytes`，类型为字节（`bytes`）。
2. 函数调用了之前提到的`hex_str`函数，将`input_bytes`转换为ASCII编码的十六进制格式的字符串。
3. 接着，函数使用`repr`函数对`input_bytes`进行转换，得到一个 Python 表示形式的字符串。
4. 最后，函数将前面的两个结果以空格连接起来，并返回一个新的字符串。

例如，如果`input_bytes`的值为`b'Hello'`，则函数将返回字符串`"48 65 6c 6c 6f b'Hello'"`，其中`48 65 6c 6c 6f`是字节数据`b'Hello'`的ASCII编码的十六进制表示，`b'Hello'`是对字节数据的Python表示。

#### hex_str(s)

该函数用于将字节数据转换为十六进制格式的字符串。

**实现思路：**

1. 函数接收一个参数`s`，类型为字节（`bytes`）。
2. 函数通过使用列表推导式和`format`方法，将字节数据`s`中的每个字节转换为两位的十六进制格式，并存储在一个列表中。
3. 最后，函数使用空格将列表中的元素连接成一个字符串，并将结果返回。

```python
return " ".join("{:02x}".format(b) for b in bytearray(s))
```

