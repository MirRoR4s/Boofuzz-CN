Session
=======

.. autoclass:: boofuzz.Session
    :members:
    :undoc-members:
    :show-inheritance:

.. automethod:: boofuzz.Session._generate_mutations_indefinitely
.. automethod:: boofuzz.Session._main_fuzz_loop

Request-Graph visualisation options
-----------------------------------

The following methods are available to render data, which can then be used to visualise the request structure.

.. automethod:: boofuzz.Session.render_graph_gml
.. automethod:: boofuzz.Session.render_graph_graphviz
.. automethod:: boofuzz.Session.render_graph_udraw
.. automethod:: boofuzz.Session.render_graph_udraw_update