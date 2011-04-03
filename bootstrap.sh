#!/bin/sh

aclocal -I aclocal && autoconf && autoheader && libtoolize --force && automake -a --foreign
