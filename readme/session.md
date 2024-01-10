# Session



### WEB 页面

Boofuzz 在进行模糊测试的时候会启动一个 web 服务器实例，允许我们查看模糊测试的执行情况。该服务器默认情况下位于 localhost 的 26000 端口。在 Session 类的构造函数中传入 web\_port（int）和 web\_address（str）可以控制 web 服务器开放的 ip 和 端口。

