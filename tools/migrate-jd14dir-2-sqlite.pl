#!/usr/pkg/bin/perl -w

#<license>
# Copyright (c) 2008 BBN Technologies Corp.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of BBN Technologies nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY BBN TECHNOLOGIES AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL BBN TECHNOLOGIES OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#</license>

use strict;
use XML::Simple;
use Data::Dumper;
use Getopt::Long;

#This script essentially uses the perl XML parser XML::Simple to put things into internal perl structures.
#It then simply tries to manipulate those perl structures to output the necessary SQL commands.

#Run it in the directory with the jabberd1.4 xml files. 


my @description=" goes through a jabberd 1.4 spool directory and creates a file of sql commands to use to upgrade to a jabberd2 database and the jabberd2 database if it can find a schema file.";

# realm
my $realm = "j.jabber.com";
# intermediate file that has the sql commands - could be more useful
# than just for sql
my $sqlfile = "tsql";
# since we're using sqlite - this is where jabberd2 put the sqlite schema
my $schema = "/usr/pkg/share/examples/jabberd/db-setup.sqlite";
# jabberd2 db
my $jabberdb = "jabberd2.db";

#temporary variables
my $file;
my $count = 0;
my $rcount = 1;
my $vcount = 1;
my $debug = 0;

#get command line arguments
if ( @ARGV > 0 ) {
    GetOptions ('d' => \$debug,
		'r|realm=s' => \$realm,
		's|schema=s' => \$schema,
		'j|jabberdb=s' => \$jabberdb,
		'help' => \&usage);
}


#open the sqlfile to put commands in
open(TSQL, ">$sqlfile");

# I'm going through each file in the directory that has a .xml suffix
# I'm using the XML::Simple parser, and to debug things you can look at
# what the Dumper($data) puts out so that the perl structures can be inspected
opendir(DIR, ".") or die "can't opendir .: $!";
while (defined($file = readdir(DIR))) {
    if($file =~ /\.xml/) {
	if($debug)
	{
	    print "$file\n";
	}

	#ForceArray causes all nested elements to be represented as arrays.
	#KeepRoot causes the name of the root element to be kept on input and output
	my $simple = XML::Simple->new (ForceArray => 1, KeepRoot => 1);
	my $data   = $simple->XMLin($file);
	
	my @filewords = split(/\./, $file);

	my $DISPATCHER = {
	    'active'   => \&migrate_active,
	    'auth'   => \&migrate_auth,
	    'roster' => \&migrate_roster,
	};

	
	if($debug) {
	    print Dumper ($data);

	    print $data->{xdb};
	    print "\n\nElements\n";
	    
	    for my $el (@{$data->{xdb}}) {
		print $el . "\n";
		foreach my $el1 (sort keys %{$el}) {
		    print "$el1: ";
		    print $el->{$el1}; 
		}
	    }

	    print $data->{xdb}->[0] . "\n";
	    print "$filewords[0]: $data->{xdb}->[0]->{password}->[0]->{content} \n";
	}

	#This is where we are putting in jabber users, need to populate both the authreg table and the
        #active table.
	#INSERT INTO "authreg" VALUES('tester1','realm','user');
	print TSQL "insert into \"authreg\" VALUES('$filewords[0]', '$realm', '$data->{xdb}->[0]->{password}->[0]->{content}');\n";
	
	$count++;
	#INSERT INTO "active" VALUES('user',4, 1201999999);
	print TSQL "insert into \"active\" VALUES('$filewords[0]\@$realm', $count, 120199999);\n";


	#This is where we're looking for roster information
	#this is an array of hashes
	my $iqarray = $data->{xdb}->[0]->{query};

	my $qelem;
	my $icount = 0;
	
	#iterate through the array of hashes looking for the roster "item" hash
	#Roster stuff is put into the roster-items table, and only subscriptions that
	#are both are carried over
	#INSERT INTO "roster-items" VALUES('tester2@host.t.com',1,'buddy1',NULL,0,0,1);
	#INSERT INTO "roster-items" VALUES('tester2@host.t.com',2,'buddy2','bud2-alias',1,1,0);

	foreach $qelem (@{$iqarray}) {
	    if($debug) {
		print "$icount : $qelem - ";
	    }
	    #for each hash, look for the roster items
	    foreach my $el1 (sort keys %{$qelem}) {
		if ($el1 =~ /item/) {
		    #represented as an array
		    my $rarray = $qelem->{item};
		    
		    #Unfortunately the way some clients stored data, roster data is represented as
		    #an ARRAY, but sometimes it gets dumped out as a HASH

		    if (ref($rarray) eq "ARRAY") {
			foreach my $budhash (@{$rarray}) {
			    ###CHECK THAT subscription is both####
			    
			    if($budhash->{subscription} =~ /both/) {
				#dump data for the roster, which is in hash form
				print TSQL "insert into \"roster-items\" VALUES('$filewords[0]\@$realm', $rcount, '$budhash->{jid}', NULL, 1, 1, 0);\n";
				
				#have to check for valid group
				my $barray ;
				if (exists($budhash->{group})) {
				    $barray = $budhash->{group}->[0];
				} 
				else {
				    $barray = "General";
				}

				print TSQL "insert into \"roster-groups\" VALUES('$filewords[0]\@$realm', $rcount, '$budhash->{jid}', '$barray');\n";
				$rcount++;
			    }
		    
			}
		    }
		    else {
#			print "IT MUST BE A HASH\n";
			foreach my $bud (sort keys %{$rarray}) {
		    	    if($rarray->{$bud}->{subscription} =~ /both/) {
			        print TSQL "insert into \"roster-items\" VALUES('$filewords[0]\@$realm', $rcount, '$rarray->{$bud}->{jid}', NULL, 1, 1, 0);\n";

         			my $barray;
				if (exists($rarray->{$bud}->{group})) {
				    $barray = $rarray->{$bud}->{group}->[0];
				} 
				else {
				    $barray = "General";
				}

				print TSQL "insert into \"roster-groups\" VALUES('$filewords[0]\@$realm', $rcount, '$rarray->{$bud}->{jid}', '$barray');\n";
				$rcount++;
			    }
			}
		    }
		    
		}
	    }
	    $icount++;
	}

	#The decision was just to move photo, fullname, email, and url if they
	#were specified.  Not so elegant but it works.
	#starting with vCard information
	#this is an array
	my $vCarray;
	my $photoInfo = "NULL";
	my $photoType = "NULL";
	my $fname = "NULL";
	my $email = "NULL";
	my $url = "NULL";
	my $tstring = "NULL";
	
	if (exists($data->{xdb}->[0]{vCard})) {
	    # it exists
	    $vCarray = $data->{xdb}->[0]->{vCard};
	    if (exists($vCarray->[0]{PHOTO})) {
		if($debug)
		{
		    print "vCarray is $vCarray->[0]->{PHOTO}\n";
		    print "PHOTO is $vCarray->[0]->{PHOTO}->[0]->{BINVAL}->[0]\n";
		}
		$photoInfo = $vCarray->[0]->{PHOTO}->[0]->{BINVAL}->[0];
		if (exists($vCarray->[0]->{PHOTO}->[0]{TYPE})) {
		    if($debug)
		    {
			print "TYPE is $vCarray->[0]->{PHOTO}->[0]->{TYPE}->[0]\n";
		    }
		    $photoType = $vCarray->[0]->{PHOTO}->[0]->{TYPE}->[0];
		}
	    }
	   
	    if (exists($vCarray->[0]{FN})) {
		if($debug)
		{
		    print "FULLNAME is $vCarray->[0]->{FN}->[0]\n";
		}

		$fname = $vCarray->[0]->{FN}->[0];
		#deal with FN being an empty hash reference and ignoring it.
		if (ref($fname) ne "")
		{
		    $fname = "NULL";
		}
	    }
	
	    if (exists($vCarray->[0]{EMAIL})) {

		if($debug)
		{
		    print "EMAIL is $vCarray->[0]->{EMAIL}->[0]\n";
		}

		#see if we can get the email here
		$email = $vCarray->[0]->{EMAIL}->[0];


		#it might be a hash that holds a hash with a USERID key
		if (ref($vCarray->[0]->{EMAIL}->[0]) eq "HASH") {
		    if (exists($vCarray->[0]->{EMAIL}->[0]{USERID})) {
			if($debug)
			{
			    print "EMAIL is actually $vCarray->[0]->{EMAIL}->[0]->{USERID}->[0]\n";
			}
			$email = $vCarray->[0]->{EMAIL}->[0]->{USERID}->[0];
		    }
		}
		#deal with EMAIL being an empty hash reference and ignoring it.
		if (ref($email) ne "")
		{
		    $email = "NULL";
		}

	    }
	
	    if (exists($vCarray->[0]{URL})) {
		if($debug)
		{
		    print "URL is $vCarray->[0]->{URL}->[0]\n";
		}

		$url = $vCarray->[0]->{URL}->[0];

		#deal with URL being an empty hash reference and ignoring it.
		if (ref($url) ne "")
		{
		    $url = "NULL";
		}
	    }

	    #have to look at the schema to figure out what is no longer NULL if you want to import the data
	    $tstring ="insert into \"vcard\" VALUES('$filewords[0]\@$realm', $vcount, '$fname',NULL,'$url',NULL,'$email',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'$photoType','$photoInfo',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);\n";
	    $tstring =~ s/\'NULL\'/NULL/g;
	    print TSQL $tstring;
	    $vcount++;
	} 
	
    }
}


closedir(DIR);

if(-r $schema)
{
    system("/usr/pkg/bin/sqlite3 $jabberdb < $schema");
    system("/usr/pkg/bin/sqlite3 $jabberdb < $sqlfile");
}

#===============================================
sub usage{
    printf ("\nUsage:\n");
    printf ("     migrate-dir.pl -r <realm> \n");
    printf ("        where <realm> is the jabberd2 realm\n");
    printf ("     migrate-dir.pl -s <schemafile> \n");
    printf ("        where <schemafile> shows the sqlite schema for jabberd2 (/usr/pkg/share/examples/jabberd/db-setup.sqlite)\n");
    printf ("     migrate-dir.pl -j <jabberdb> \n");
    printf ("        where <jabberdb> is the name for the output jabber2db (defaults to jabberd2.db)\n");
    printf ("     migrate-dir.pl -d \n");
    printf ("        which turns on debugging \n");
    printf ("     migrate-dir.pl -h \n");
    printf ("        prints this message \n");
    printf ("\nDescription:\n");
    printf ("     @description\n");
    exit(1);

}

