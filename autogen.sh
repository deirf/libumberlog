#! /bin/sh

libtoolize --force --copy --automake
aclocal -I m4 --install
autoheader
automake --foreign --add-missing --copy
autoconf
