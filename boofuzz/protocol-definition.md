---
description: https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html
---

# Protocol Definition

协议定义就是用Boofuzz的原语描绘协议的字段，Boofuzz 提供了很多个原语，适用于不同类型的字段。

## Request

Request 类的实例就相当于一个模糊测试用例，我们可以对它进行模糊测试。一个 Request 类实例通常由多个 Block 和 Primitives 构成。

## Block

块（Block）可以包含原语以及一些辅助字段。（比如 sizers、checksums等）