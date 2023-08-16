# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import sys
sys.path.insert(0,os.path.abspath('.'))
project = 'rainfuzz'
copyright = 'boofuzz'
author = 'MirRoR4s'
version = "0.0"
release = '0.0'
language = "en"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration


templates_path = ['_templates']
exclude_patterns = []
extensions = [

'sphinx.ext.autodoc','sphinx.ext.napoleon','sphinx.ext.viewcode'
        ]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme' # 到时候上传记得注释掉这个
#html_static_path = ['_static']
