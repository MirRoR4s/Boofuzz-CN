环境搭建
========

操作系统环境：\ **WSL-ubuntu22.04**

1. 跟随这篇博客直至支持 Markdown 步骤 `Read the
   Docs <https://luhuadong.blog.csdn.net/article/details/109006380?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2~default~CTRLIST~Rate-1.pc_relevant_antiscan&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2~default~CTRLIST~Rate-1.pc_relevant_antiscan&utm_relevant_index=1>`__
2. 安装 MyST 支持 Markdown

.. code:: shell

   pip install myst-parser

之后在conf.py下：

::

   extentions = ["myst_parser"]

详情请参看：\ `Getting started with Sphinx — Read the Docs user
documentation <https://docs.readthedocs.io/en/stable/intro/getting-started-with-sphinx.html>`__

3. 由于read the
   docs正进行配置文件的更新，所以现在进行文档托管时要额外编写一个名为\ ``.readthedocs.yaml``\ 的配置文件。

我的内容如下:

.. code:: yaml

   version: 2

   build:
     os: "ubuntu-22.04"
     tools:
       python: "3.10"
   sphinx:
     fail_on_warning: true

   formats:
     - pdf
     - epub

   python:
     install:
       - requirements: ./requirements.txt

4. 也可以不安装 markdown 支持插件，而是直接编写 markdown 并将其转为 rst

代码如下：

.. code:: python

   
   sudo apt install pandoc
   pandoc -f markdown -t rst input.md -o output.rst

详情可参看\ `官方文档 <https://docs.readthedocs.io/en/stable/tutorial/index.html>`__\ 。
