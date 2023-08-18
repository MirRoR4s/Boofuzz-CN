import warnings

from . import pedrpc
from .base_monitor import BaseMonitor


# Important: BaseMonitor needs to come *before* pedrpc.Client in the
# Inheritance list for the method resolution order to produce
# correct results.


class ProcessMonitor(BaseMonitor, pedrpc.Client):
    """
    ProcessMonitor 类继承自 BaseMonitor 以及 pedrpc.Client，是 process monitor 接口的代理类。

    在 0.2.0 版本之前，boofuzz 的网络和进程监视器是在 RPC 之上进行通信的，
    RPC 客户端被直接传递给 Session 类，并在 RPC partner 上动态地解析所有方法调用。

    .. Proxy class for the process monitor interface.

     In Versions < 0.2.0, boofuzz had network and process monitors
     that communicated over RPC. The RPC client was directly passed
     to the session class, and resolved all method calls dynamically
     on the RPC partner.
    
    自 0.2.0 版本以后，每个 monitor 类都必须实现抽象类 BaseMonitor。
    它定义了所有 monitor 之间的公共接口。 
    为了有助于以后的类型提示工作并消除网络和进程监视器的歧义，
    引入了这个显式代理类，它将所有调用快速转发到 RPC partner。

    .. Since 0.2.0, every monitor class must implement the abstract class
     BaseMonitor, which defines a common interface among all Monitors. To
     aid future typehinting efforts and to disambiguate Network- and Process Monitors,
     this explicit proxy class has been introduced that
     fast-forwards all calls to the RPC partner.

    .. versionadded:: 0.2.0
    """

    def __init__(self, host, port):
        BaseMonitor.__init__(self)
        pedrpc.Client.__init__(self, host, port)

        self.server_options = {}
        self.host = host
        self.port = port

    def alive(self):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("alive")

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("pre_send", session.total_mutant_index)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("post_send")

    def set_options(self, *args, **kwargs):
        """
        旧的 RPC 接口指明用 set_foobar 方法设置选项，但是不同的 RPC 会实现不同的 set_foobar，
        所以 set_options 方法负责转换参数后传给 set_foobar。

        .. The old RPC interfaces specified set_foobar methods to set options.
         As these vary by RPC implementation, this trampoline method translates
         arguments that have been passed as keyword arguments to set_foobar calls.
        
        如果你调用 ``set_options(foobar="barbaz")``，那么实际上是在 RPC partner 上调用 ``set_foobar("barbaz")``。
          
        .. If you call ``set_options(foobar="barbaz")``, it will result in a call to
         ``set_foobar("barbaz")`` on the RPC partner.
        """
        # args will be ignored, kwargs will be translated

        for arg, value in kwargs.items():
            eval("self.__method_missing('set_{0}', kwargs['{0}'])".format(arg))

        self.server_options.update(**kwargs)

    def get_crash_synopsis(self):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("get_crash_synopsis")

    def start_target(self):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("start_target")

    def stop_target(self):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("stop_target")

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        """This method is forwarded to the RPC daemon."""
        return self.__method_missing("restart_target")

    def on_new_server(self, new_uuid):
        """Restores all set options to the RPC daemon if it has restarted since the last call."""
        for key, val in self.server_options.items():
            self.__hot_transmit(("set_{}".format(key), ((val,), {})))

    def set_proc_name(self, new_proc_name):
        """.. deprecated :: 0.2.0

        This option should be set via ``set_options``.
        """
        warnings.warn(
            "This method is deprecated and will be removed in a future Version of boofuzz."
            " Please use set_options(log_path=...) instead.",
            FutureWarning,
        )

        return self.set_options(proc_name=new_proc_name)

    def set_start_commands(self, new_start_commands):
        """.. deprecated :: 0.2.0

        This option should be set via ``set_options``.
        """
        warnings.warn(
            "This method is deprecated and will be removed in a future Version of boofuzz."
            " Please use set_options(log_path=...) instead.",
            FutureWarning,
        )

        return self.set_options(start_commands=new_start_commands)

    def set_stop_commands(self, new_stop_commands):
        """.. deprecated :: 0.2.0

        This option should be set via ``set_options``.
        """
        warnings.warn(
            "This method is deprecated and will be removed in a future Version of boofuzz."
            " Please use set_options(log_path=...) instead.",
            FutureWarning,
        )

        return self.set_options(stop_commands=new_stop_commands)

    def set_crash_filename(self, new_crash_filename):
        """.. deprecated :: 0.2.0

        This option should be set via ``set_options``.
        """
        warnings.warn(
            "This method is deprecated and will be removed in a future Version of boofuzz."
            " Please use set_options(log_path=...) instead.",
            FutureWarning,
        )

        return self.set_options(crash_filename=new_crash_filename)

    def __repr__(self):
        return "ProcessMonitor#{}[{}:{}]".format(id(self), self.host, self.port)
