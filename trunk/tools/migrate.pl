#!/usr/bin/perl -w

#
# jabberd 1.4 -> 2.0 migration tool
# Copyright (c) 2003 Robert Norris
# GPL v2. See http://www.gnu.org/copyleft/gpl.html for more info
#

# 
# This can migrate from any 1.4 XDB source, into 2.0 MySQL or
# PostgreSQL databases. Other 2.0 databases (such as Berkeley) are not
# supported at this time.
# 
# Currently, this can migrate authentication information and rosters.
# Anything more than that, you're on your own.
#
# There's very little error checking. If you find some user data that
# consistently breaks, please file a bug report with some sample data.
#

#
# Installation
#
# 1. Install the following Perl packages
#
#    - XML::Stream 1.17 or higher (from JabberStudio)
#    - Net::Jabber 1.29 or higher (from JabberStudio)
#    - Digest::SHA1
#    - DBI
#    - DBD::Pg or DBD::mysql
#
# 2. Make sure the appropriate database schema is imported into your
#    database (db-setup.mysql or db-setup.pgsql)
#
# 3. Add something like the following to your 1.4 jabber.xml:
#
#      <service id="migrate">
#        <accept>
#          <ip>127.0.0.1</ip>
#          <port>7000</port>
#          <secret>secret</secret>
#        </accept>
#      </service>
#   
# 4. Create a file with the JIDs of the users you wish to migrate, one
# per line.
#
# 5. Edit the config below to taste.
#
# 6. Run.
#

# host/port that jabberd 1.4 is listening for this component on
my $COMP_HOST   = 'localhost';
my $COMP_PORT   = 7000;
# name of component
my $COMP_NAME   = 'migrate';
# component secret
my $COMP_SECRET = 'secret';

# backend database type (either 'mysql' or 'pgsql')
my $DB_TYPE     = 'mysql';
# host/port of the database server
my $DB_HOST     = 'localhost';
my $DB_PORT     = 3306;     # 5432 is default for pgsql
# database name
my $DB_NAME     = 'jabberd2';
# database user/pass
my $DB_USER     = 'jabberd2';
my $DB_PASS     = 'secret';

# file containing user list
my $USER_FILE   = "migrate-users";

# data types to migrate
my @DATA_TYPES  = qw(roster active auth);

# authentication realm for migrated users
my $AUTH_REALM  = 'gideon.its.monash.edu.au';

#
# you shouldn't need to touch anything below here
#

use strict;

use DBI;
use Digest::SHA1 qw(sha1_hex);

#
# all of this madness is to work around problems and shortcomings with Net::Jabber
# 
use Net::Jabber::XDB;
$Net::Jabber::XDB::FUNCTIONS{XDB}->{XPath}->{Type} = 'master';

use Net::Jabber 1.29 qw(Component);

package Net::Jabber::XDB;

$FUNCTIONS{Data}->{XPath}->{Type}  = 'node';
$FUNCTIONS{Data}->{XPath}->{Path}  = '*[@xmlns]';
$FUNCTIONS{Data}->{XPath}->{Child} = 'Data';
$FUNCTIONS{Data}->{XPath}->{Calls} = ['Get','Defined'];

package Net::Jabber::Data;

$FUNCTIONS{XMLNS}->{XPath}->{Path} = '@xmlns';

$FUNCTIONS{Data}->{XPath}->{Type} = 'node';
$FUNCTIONS{Data}->{XPath}->{Path} = '*[@xmlns]';
$FUNCTIONS{Data}->{XPath}->{Child} = 'Data';
$FUNCTIONS{Data}->{XPath}->{Calls} = ['Get','Defined'];

my $ns;

$ns = 'jabber:iq:auth';

$NAMESPACES{$ns}->{Password}->{XPath}->{Path} = 'text()';

$NAMESPACES{$ns}->{Auth}->{XPath}->{Type} = 'master';

$ns = 'jabber:iq:register';

$NAMESPACES{$ns}->{Register}->{XPath}->{Type} = 'master';

$ns = 'jabber:iq:roster';

$NAMESPACES{$ns}->{Item}->{XPath}->{Type} = 'node';
$NAMESPACES{$ns}->{Item}->{XPath}->{Path} = 'item';
$NAMESPACES{$ns}->{Item}->{XPath}->{Child} = ['Data','__netjabber__:iq:roster:item'];
$NAMESPACES{$ns}->{Item}->{XPath}->{Calls} = ['Add'];

$NAMESPACES{$ns}->{Items}->{XPath}->{Type} = 'children';
$NAMESPACES{$ns}->{Items}->{XPath}->{Path} = 'item';
$NAMESPACES{$ns}->{Items}->{XPath}->{Child} = ['Data','__netjabber__:iq:roster:item'];
$NAMESPACES{$ns}->{Items}->{XPath}->{Calls} = ['Get'];

$ns = '__netjabber__:iq:roster:item';

$NAMESPACES{$ns}->{Ask}->{XPath}->{Path} = '@ask';

$NAMESPACES{$ns}->{Group}->{XPath}->{Type} = 'array';
$NAMESPACES{$ns}->{Group}->{XPath}->{Path} = 'group/text()';

$NAMESPACES{$ns}->{JID}->{XPath}->{Type} = 'jid';
$NAMESPACES{$ns}->{JID}->{XPath}->{Path} = '@jid';

$NAMESPACES{$ns}->{Name}->{XPath}->{Path} = '@name';

$NAMESPACES{$ns}->{Subscription}->{XPath}->{Path} = '@subscription';

$NAMESPACES{$ns}->{Item}->{XPath}->{Type} = 'master';

package main;
#
# end madness
#

$| = 1;

print "Loading user file\n";

open IN, $USER_FILE or die "couldn't open $USER_FILE for reading: $!";
my @users = grep { chomp } <IN>;
close IN;

die "unknown database type '$DB_TYPE'" if $DB_TYPE ne 'mysql' and $DB_TYPE ne 'pgsql';

print "Connecting to database\n";

my $dbh;
eval {
    if($DB_TYPE eq 'mysql') {
        $dbh = DBI->connect("dbi:mysql:dbname=$DB_NAME;host=$DB_HOST;port=$DB_PORT", $DB_USER, $DB_PASS, { AutoCommit => 0, RaiseError => 1 });
    } else {
        $dbh = DBI->connect("dbi:Pg:dbname=$DB_NAME;host=$DB_HOST;port=$DB_PORT", $DB_USER, $DB_PASS, { AutoCommit => 0, RaiseError => 1 });
    }
};
if($@) {
    die "db connect error: $@";
}

print "Connecting to jabber server\n";

my $c = new Net::Jabber::Component(
#    debuglevel => 1, debugfile => 'stdout', debugtime => 0
);
$c->Connect(
    hostname        => $COMP_HOST,
    port            => $COMP_PORT,
    secret          => $COMP_SECRET,
    componentname   => $COMP_NAME,
    connectiontype  => 'accept');

$c->Connected or die "$0: connect to jabber server failed";

my ($iq, $xdb, $res);

print scalar @users, " users to migrate\n";

foreach my $user (@users) {
    print "Converting data for $user...\n";

    my $data = { };
    for(@DATA_TYPES) {
        print "  $_\n";
        eval '_migrate_'.$_.'($data, $user)';
        warn "$@" if $@;
    }

    print "Writing to database... ";

    eval {
        my ($rows, $tables) = (0, 0);

        foreach my $type (keys %$data) {
            foreach my $item (@{$data->{$type}}) {
                my $sql = 'INSERT INTO ' . _sql_literal($type) . " ( ";
                for(keys %$item) {
                    $sql .= _sql_literal($_) . ', ';
                }
                $sql =~ s/, $/) VALUES ( /;
                for(keys %$item) {
                    $sql .= $item->{$_} . ', ';
                }
                $sql =~ s/, $/)/;

                $dbh->do($sql);

                $rows++;
            }

            $tables++;
        }

        $dbh->commit;

        print "inserted $rows rows into $tables tables.\n";
    };
    if($@) {
        warn "db error: $@";
        $dbh->rollback;
    }
}

$dbh->disconnect;

sub _sql_literal {
    my $arg = shift;
    return "\"$arg\"" if $DB_TYPE eq 'pgsql';
    return "\`$arg\`";
}

sub _xdb_get {
    my ($user, $ns) = @_;

    my $xdb = new Net::Jabber::XDB;
    $xdb->SetXDB(
        to => $user,
        from => $COMP_NAME,
        type => 'get',
        ns => $ns);

    return $c->SendAndReceiveWithID($xdb);
}

sub _object_quote {
    $dbh->quote(shift);
}
        
sub _object_new {
    my $item;

    $item->{'collection-owner'} = _object_quote(shift);
    $item->{'object-sequence'} = "nextval('object-sequence')" if $DB_TYPE eq 'pgsql';

    return $item;
}

sub _migrate_roster {
    my ($data, $user) = @_;

    my $xdb = _xdb_get($user, 'jabber:iq:roster');
    my $roster = $xdb->GetData or return;

    my @items = $roster->GetItems;
    for(@items) {
        my $item = _object_new($user);
        $item->{'jid'} = _object_quote($_->GetJID);
        $item->{'name'} = _object_quote($_->GetName) if $_->GetName;
        
        my $s10n = $_->GetSubscription;
        if(not $s10n or $s10n eq 'none') {
            $item->{'to'} = _object_quote('0');
            $item->{'from'} = _object_quote('0');
        } elsif($s10n eq 'both') {
            $item->{'to'} = _object_quote('1');
            $item->{'from'} = _object_quote('1');
        } elsif($s10n eq 'to') {
            $item->{'to'} = _object_quote('1');
            $item->{'from'} = _object_quote('0');
        } elsif($s10n eq 'from') {
            $item->{'to'} = _object_quote('0');
            $item->{'from'} = _object_quote('1');
        }

        my $ask = $_->GetAsk;
        if(not $ask) {
            $item->{'ask'} = 0;
        } elsif($ask eq 'subscribe') {
            $item->{'ask'} = 1;
        } elsif($ask eq 'unsubscribe') {
            $item->{'ask'} = 2;
        }

        push @{$data->{'roster-items'}}, $item;

        my $jid = $item->{'jid'};

        my @groups = $_->GetGroup;
        for(@groups) {
            my $item = _object_new($user);
            $item->{'jid'} = $jid;
            $item->{'group'} = _object_quote($_);

            push @{$data->{'roster-groups'}}, $item;
        }
    }
}

sub _migrate_active {
    my ($data, $user) = @_;
    
    my $item = _object_new($user);
    $item->{'time'} = time();

    push @{$data->{'active'}}, $item;
}

sub _migrate_auth {
    my ($data, $user) = @_;

    my $xdb = _xdb_get($user, 'jabber:iq:auth');
    my $auth = $xdb->GetData or return;

    my $item;
    $user =~ m/^(.*)\@/;
    $item->{'username'} = _object_quote($1);
    $item->{'realm'} = _object_quote($AUTH_REALM);

    my $pass = $auth->GetPassword;
    $item->{'password'} = _object_quote($pass);

    push @{$data->{'authreg'}}, $item;
}

sub _migrate_vcard {
    my ($data, $user) = @_;

    my $xdb = _xdb_get($user, 'vcard-temp');
    my $vcard = $xdb->GetData or return;

    # !!! implement this
}
