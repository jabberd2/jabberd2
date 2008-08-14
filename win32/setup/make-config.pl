#!/usr/bin/perl

my @file = <>;

$_ = join '', @file;
s/\r//gi;
s/localhost\.localdomain/localhost/gi;
s/\@(?:bindir|sysconfdir|localstatedir)\@/./gi;
s/\@(?:pkglibdir)\@/modules/gi;
s/\/jabberd\/(?:pid|log|db)//gi;
s/<module>mysql<\/module>/<module>sqlite<\/module>/gi;
s/type='syslog'/type='file'/gi;
s/\s*<!--\s*\n(\s*<\w+[^>]*>[^<]*\.(?:log|pem)<\/\w+>)\s*\n\s*-->[^\n]*/\n$1/gi;

print;
