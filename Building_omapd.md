# Introduction #

omapd was written in C++ using the Qt Framework from Nokia.  Current omapd development is using Qt v4.8.1, and v4.8.0 is a minimum version because of new flags to limit allowed SSL Protocols.  Note that Qt is a multi-platform product, and it hides the details of the underlying operating system from the programmer.  omapd was initially written on a Linux platform, but, using the Qt SDK, it should build and run on any other platform Qt supports.


# Details #

You will need to download a [Qt SDK development environment](http://qt.nokia.com/downloads) and install it on your computer.

Once you have the Qt SDK installed, get a version of omapd to play with.

To build with QtCreator:
  1. Use `QtCreator`  to open the RAMHashTables.pro file in the plugins/RAMHashTables directory and build
  1. Use `QtCreator`  to open the omapd.pro file in the omapd source tree.  Build and run

To build manually:
  1. Go into the appropriate plugins subdirectory (at this point only RAMHashTables)
    * Run qmake on the RAMHashTables.pro file
    * This creates a Makefile
    * Then type make
  1. At the top level omapd source directory:
    * Run qmake (part of the Qt SDK) on the omapd.pro file
    * This creates a Makefile
    * Then type make
  1. With the plugin shared library and omapd executable
    * Then execute omapd: ./omapd