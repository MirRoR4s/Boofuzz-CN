Session
=======

.. autoclass:: boofuzz.Session
    :members:
    :undoc-members:
    :show-inheritance:

boofuzz 模糊测试
^^^^^^^^^^^^^^^^^
下面的几个方法涉及到 boofuzz 框架模糊测试的具体逻辑和实现，是 boofuzz 模糊测试的精髓所在。

.. automethod:: boofuzz.Session._generate_mutations_indefinitely
.. automethod:: boofuzz.Session._main_fuzz_loop

Request-Graph visualisation options
-----------------------------------

The following methods are available to render data, which can then be used to visualise the request structure.

.. automethod:: boofuzz.Session.render_graph_gml
.. automethod:: boofuzz.Session.render_graph_graphviz
.. automethod:: boofuzz.Session.render_graph_udraw
.. automethod:: boofuzz.Session.render_graph_udraw_update