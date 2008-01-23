#!/usr/bin/perl -w

################################################################################
# dumpbdb.pl
#
# Dump a Jabberd2 SM BerkeleyDB.
#
# The DB file given on the command line is dumped as an XML file to stdout. 
#
# NB:
# - integer types are hard-coded to be 4 bytes LSB
#
# (c) 2007 Harald Braumann <harry@unheit.net>
#
# This software is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# This package is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You can view the GNU General Public License at 
# http://www.gnu.org/licenses/gpl.html.
#
################################################################################

use BerkeleyDB;

# set to one to enable debug output
$DEBUG = 1;

# berkeleydb file
$db_file = "";

# object type identifiers
%db_object_types = (0 => "boolean", 1 => "integer", 2 => "string", 3 => "nad", 4 => "unknown");

# used for the print_ident function
$indent = 0;
$inc_indent = 2;


sub trc {
    $0 =~ s,.*/,,;
    print STDERR "$0: @_\n";
}

sub trcdebug {
    trc("@_") if $DEBUG;
}

sub error {
    trc("@_");
    exit 1;
}

sub usage {
    trc <<EOF
usage dumpdb <db file>
EOF
}

sub options {
    $db_file = shift(@ARGV) || usage() && error;
}

#print_indent $str
sub print_indent {
    my $str = shift;
    printf("%*s%s", $indent, "", $str);
}

# get_string $value
# $value is an array ref
# strings are delimited by a binary 0
sub get_string {
    my $value = shift;
    my $pos;

    for ($pos = 0; ord($value->[$pos]) != 0; $pos++) {}

    my @str_arr = splice(@$value, 0, $pos);
    splice(@$value, 0, 1); # remove the 0

    return join('', @str_arr);
}

# get_int $value
# $value is an array ref
# int is encoded 4 bytes LSB
sub get_int {
    my $value = shift;
    
    my $int = ord($value->[3]) << 24 | ord($value->[2]) << 16 | ord($value->[1]) << 8 | ord($value->[0]);
    splice(@$value, 0, 4);
    return $int;
}

#dump_fields $value
sub dump_fields {
    my @value = split(//, shift);
    my $cur = 0;

    while ($#value > 0) {
        my $field = get_string(\@value);
        my $type_id = get_int(\@value);
        my $type = $db_object_types{$type_id};
        defined $type || error("error: undefined type id: $type_id");
        print_indent("<$field type=\"$type\">");
        if ($type eq "integer") {
            printf("%i", get_int(\@value));
        } elsif ($type eq "boolean") {
            printf("%s", get_int(\@value) > 0 ? "1" : "0");
        } elsif ($type eq "string") {
            print("<![CDATA[".get_string(\@value)."]]>");
        } elsif ($type eq "nad") {
            print("<![CDATA[".get_string(\@value)."]]>");
        } elsif ($type eq "unknown") {
            trc("warn: `unknown\' type found. don't know how to parse!");
            print("<![CDATA[".join('', @value)."]]>");
            $#value = 0;
        } else {
            trc("warn: unknown type found!");
            print("<![CDATA[".join('', @value)."]]>");
            $#value = 0;
        }            
        printf("</$field>\n");
    }
}

#dump_db $db_name
sub dump_db {
    my $db_name = shift;
    my $db;
    my $cursor;
    my ($key, $value) = ("", "");

    trcdebug("dump db $db_name ...");

    $db = new BerkeleyDB::Hash -Filename => $db_file, -Subname => $db_name, -Flags => DB_RDONLY ||
        error("Error opening $db_file/$db_name: $BerkeleyDB::Error");
    defined $db || error("Error opening $db_file/$db_name: $BerkeleyDB::Error");

    $cursor = $db->db_cursor() || error "could not get cursor: $BerkeleyDB::Error" ;

    print_indent("<$db_name>\n");
    $indent += $inc_indent;

    while ($cursor->c_get($key, $value, DB_NEXT) == 0) {
        print_indent("<entry key=\"$key\">\n");
        $indent += $inc_indent;
        
        dump_fields($value);

        $indent -= $inc_indent;
        print_indent("</entry>\n");
    }

    $indent -= $inc_indent;
    print_indent("</$db_name>\n");

    trcdebug("dump db $db_name OK");
}

options();


trcdebug("open db $db_file ...");
$db = new BerkeleyDB::Unknown -Filename => $db_file, -Flags => DB_RDONLY || 
    error "error opening $db_file: $BerkeleyDB::Error";
defined $db || error "error opening $db_file: $BerkeleyDB::Error";
trcdebug("OK");

trcdebug("walking sub dbs ...");
$cursor = $db->db_cursor() || error "could not get cursor: $BerkeleyDB::Error" ;

($k, $v) = ("", "") ;

print_indent("<sm-bdb>\n");
$indent += $inc_indent;
while ($cursor->c_get($k, $v, DB_NEXT) == 0) { 
    trcdebug("found sub db $k");
    dump_db($k);
}
$indent -= $inc_indent;
print_indent("</sm-bdb>\n");
