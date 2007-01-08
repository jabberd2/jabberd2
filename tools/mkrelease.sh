#!/bin/bash

[[ $# -ne 2 ]] && { echo "Usage: `basename $0` http://...svn/path RELEASE_NUMBER" >&2; exit 1;}

APPNAME=jabberd
APPVER=$2
TMPDIR=`mktemp`
DSTDIR=`pwd`
rm -rf "$TMPDIR"
mkdir "$TMPDIR"
cd "$TMPDIR"
svn -q export "$1" "$APPNAME-$APPVER"
cd "$APPNAME-$APPVER"
sed -i "s/^AC_INIT([a-z]\+.*, [0-9]\+.*)$/AC_INIT($APPNAME, $APPVER)/" configure.in
./bootstrap
cd ..
tar zcf "$DSTDIR/$APPNAME-$APPVER.tar.gz" "$APPNAME-$APPVER"
tar jcf "$DSTDIR/$APPNAME-$APPVER.tar.bz2" "$APPNAME-$APPVER"
cd "$DSTDIR"
ls -l "$APPNAME-$APPVER.tar."{gz,bz2}

