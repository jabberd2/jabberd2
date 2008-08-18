#!/usr/bin/perl

my @file = <>;

$_ = join '', @file;
s/\r//gi;
s/localhost\.localdomain/localhost/gi;
s/\@(?:bindir|sysconfdir|localstatedir)\@/./gi;
s/\@(?:pkglibdir)\@/modules/gi;
s/\/jabberd\/(?:pid|log|db|stats)//gi;
s/we use the MySQL driver for all storage/we use the SQLite driver for all storage/gi;
s/<driver>mysql<\/driver>/<driver>sqlite<\/driver>/gi;
s/<module>mysql<\/module>/<module>sqlite<\/module>/gi;
s/type='syslog'/type='file'/gi;
s/\s*<!--\s*\n(\s*<\w+[^>]*>[^<]*\.(?:log|pem)<\/\w+>)\s*\n\s*-->[^\n]*/\n$1/gi;
s/<id register-enable='true'>localhost/<id register-enable='true' pemfile='.\/server.pem'>localhost/gi;

print;
