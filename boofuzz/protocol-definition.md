---
description: https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html
---

# Protocol Definition

协议定义要求用Boofuzz的原语描绘协议的字段，一个针对HTTP协议的协议定义如下：

```python
req = Request("HTTP-Request", children=(
    
```
