#!/bin/bash

[[ $# -ne 2 ]] && { echo "Usage: `basename $0` http://...svn/path RELEASE_NUMBER" >&2; exit 1;}

APPNAME=jabberd
APPVER=$2
TMPDIR=`mktemp`
DSTDIR=`pwd`
rm -rf "$TMPDIR"
mkdir "$TMPDIR"
cd "$TMPDIR"
svn -q copy "$1" `dirname "$1"`"/tags/$APPNAME-$APPVER" -m "Tagging $APPVER release"
svn -q export "$1" "$APPNAME-$APPVER"
cd "$APPNAME-$APPVER"
sed -i "s/^AC_INIT(.*$/AC_INIT(\[$APPNAME\], \[$APPVER\], \[jabberd2@xiaoka.com\])/" configure.ac
autoreconf --install --force
libtoolize --copy --force
./configure
make dist
gzip -dc < "$APPNAME-$APPVER.tar.gz" | bzip2 -z9c > "$DSTDIR/$APPNAME-$APPVER.tar.bz2"
mv -f "$APPNAME-$APPVER.tar.gz" "$DSTDIR/"
cd "$DSTDIR"
ls -l "$APPNAME-$APPVER.tar."{gz,bz2}

