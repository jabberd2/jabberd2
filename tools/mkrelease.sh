#!/bin/bash

[[ $# -ne 2 ]] && { echo "Usage: `basename $0` http://...svn/path RELEASE_NUMBER" >&2; exit 1;}

APPNAME=jabberd
APPVER=$2
TMPDIR=`mktemp`
DSTDIR=`pwd`
SVNPATH=$1
SVNBASE=`echo "$SVNPATH" | sed 's/\(trunk\|branches\|tags\).*//'`
set -e

rm -rf "$TMPDIR"
mkdir "$TMPDIR"
cd "$TMPDIR"
svn -q checkout "$SVNPATH" "$APPNAME-$APPVER"
cd "$APPNAME-$APPVER"
sed -i "/^AC_INIT/s/\[.*\], \[.*\], /[$APPNAME], [$APPVER], /" configure.ac
autoreconf --install --force
libtoolize --copy --force
./configure
make dist
svn -q copy . "$SVNBASE/tags/$APPNAME-$APPVER" -m "Tagging $APPVER release"
gzip -dc < "$APPNAME-$APPVER.tar.gz" | bzip2 -z9c > "$DSTDIR/$APPNAME-$APPVER.tar.bz2"
mv -f "$APPNAME-$APPVER.tar.gz" "$DSTDIR/"
cd "$DSTDIR"
ls -l "$APPNAME-$APPVER.tar."{gz,bz2}

