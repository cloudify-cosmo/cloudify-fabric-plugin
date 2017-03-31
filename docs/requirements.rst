
Requirements
============

* Python versions:

  * 2.7.x
* If access to the Context Proxy (`ctx`) is required within an invoked script, then the remote host must have Python's `argparse` installed.

.. note::
    + As the fabric plugin is used for remote execution,
      the fact that it doesn't support versions of Python other than 2.7.x doesn't really mean much.
    + While `argparse` is usually provided out-of-the-box with Python 2.7.x,
      that is not the case for Python 2.6.x.
    + The requirement for `argparse` will be dropped in a future version of the plugin.
