==========
noipclient
==========

noipclient is a noip.com dynamic DNS update client.

|pypi| |build| |deps|

Installation
============

Dependencies
------------

noipclient depends on the Python development package. For example, to install it on Ubuntu:

$ sudo apt-get install python-dev

Or on CentOS:

$ sudo yum install python-devel

Installing from pypi
--------------------

You can install ``noipclient`` either via the Python Package Index (PyPI)
or from source.

To install using ``pip``,::

    $ pip install noipclient

To install using ``easy_install``,::

    $ easy_install noipclient

Downloading and installing from source
--------------------------------------

Alternatively, you can download the latest version of ``noipclient`` from
http://pypi.python.org/pypi/noipclient/

You can install it by doing the following,::

    $ tar xvfz noipclient-0.0.0.tar.gz
    $ cd noipclient-0.0.0
    # python setup.py install # as root

Using the development version
-----------------------------

You can clone the git repository by doing the following::

    $ git clone git://github.com/acordiner/noipclient.git

Using noipclient
================

To start noipclient, run:

    $ noipclient start

The first time you run the client, you will be prompted to enter your noip.com account details:

    Config file /home/fbar/.noipclient.cfg not found. Create one now? [Yn]
    no-ip.com username: fbar
    no-ip.com password:
    no-ip.com hostname (e.g. myhost.no-ip.org): foobar.no-ip.org
    Starting noipclient ... OK

You can then start, stop, restart and check the status of noipclient:

    $ noipclient status
    noipclient -- pid: 23842, status: sleeping, uptime: 0m, %cpu: 0.0, %mem: 0.1
    $ noipclient restart
    Stopping noipclient ... OK
    Starting noipclient ... OK
    $ noipclient stop
    Stopping noipclient ... OK

Bug tracker
===========

If you have any suggestions, bug reports or annoyances please report them
at http://github.com/acordiner/noipclient/issues/

License
=======

This software is licensed under the ``GPL v2 License``. See the ``LICENSE``
file in the top distribution directory for the full license text.


.. |pypi| image:: https://img.shields.io/pypi/v/noipclient.svg?style=flat-square&label=latest%20version
    :target: https://pypi.python.org/pypi/noipclient
    :alt: Latest version released on PyPi

.. |build| image:: https://img.shields.io/travis/acordiner/noipclient/master.svg?style=flat-square&label=unix%20build
    :target: http://travis-ci.org/acordiner/noipclient
    :alt: Build status of the master branch

.. |deps| image:: https://img.shields.io/requires/github/acordiner/noipclient/master.svg?style=flat-square&label=dependencies
    :target: https://requires.io/github/acordiner/csvquerytool/requirements/?branch=master
    :alt: Status of dependencies
