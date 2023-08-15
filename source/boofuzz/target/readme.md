# [Target](https://boofuzz.readthedocs.io/en/stable/source/Target.html)
## 前言

Target 是目标描述符容器。

## 成员变量与成员方法

### [\_\_init\_\_](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target)

封装连接逻辑。

**参数：**

- connection（ITargetConnection）- 到目标系统的连接对象
- monitors（List[Union[IMonitor, [pedrpc.Client](https://boofuzz.readthedocs.io/en/stable/user/other-modules.html#boofuzz.monitors.pedrpc.Client)]]）- 当前 Target 对象的监视器列表
- monitor_alive（list）- 当监视器处于活跃状态时会调用的一个函数列表
- repeater（[repeater.Repeater](https://boofuzz.readthedocs.io/en/stable/source/Target.html#boofuzz.repeater.Repeater)）- 发送时所用的 Repeater，默认为 None
- procmon - 用于添加进程监视器的接口（已弃用）
- procmon_options - 同上

**返回值：**

- Traget对象

### [close](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target.close)

关闭到目标系统的连接。

**参数：**

- None

**返回值：**

- None

**实现思路：**

1. 调用目标对应套接字的 `_target_connection.close()` 方法

### [monitors_alive()](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target.monitors_alive)

等待监视器启动（活跃）/与 RPC 服务器建立连接。当某个 target 被添加到 session 中时，target 的每一次重启都会调用该方法。

**参数：**

- None

**返回值：**

- None

**实现思路：**

- 枚举当前 Target 对象的监视器列表（`self.monitors`) 判断监视器是否处于活跃状态
- 如果某监视器处于活跃状态，那么将其作为参数传入函数列表（`self.monitor_alive`）

### [set_fuzz_data_logger(fuzz_data_logger)](https://boofuzz.readthedocs.io/en/stable/_modules/boofuzz/sessions.html#Target.set_fuzz_data_logger)

设置当前 Target 对象的 fuzz 数据记录器--用于发送和接收 fuzz 数据。

**参数：**

- fuzz_data_logger（IFuzzLogger）- 新的 logger

**返回值：**

- None

**实现思路：**

- 将传入参数直接赋值给成员变量 `self._fuzz_data_logger`
