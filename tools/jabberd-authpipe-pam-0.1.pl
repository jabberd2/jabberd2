#!/usr/bin/perl -w
#
#
# jabberd-authpipe-pam.pl version 0.1
# Allows Jabber authentication against PAM without running jabberd as root.
#
# Copyright 2006 Nicholas J Humfrey
# This code is hereby placed into the public domain.
#
#
# Configure jabberd2 by editing c2s.xml:
#
# <module>pipe</module>
#
# <pipe>
#   <!-- Program to execute -->
#   <exec>/usr/local/libexec/jabberd-authpipe-pam.pl</exec>
# </pipe>
#
# Place this script in /usr/local/libexec then run:
#   chown root jabberd-authpipe-pam.pl
#   chmod 4755 jabberd-authpipe-pam.pl
#
# This sets the script to run as suid root and gives it access to the 
# shadow password file. You man need to install perl-suid in order to 
# run perl scripts with the suid bit set.
#
# This script only implements the User-Exists and Check-Password routines.
# See docs/dev/c2s-pipe-authenticator for details about the protocol.
#
#
# To get this script to work with PSI, Ifound that I had to enable 
# "Allow Plaintext Login" in PSI. Please make sure that you use SSL 
# so that plain-text passwords aren't sent over the network.
#
#


use strict;
use MIME::Base64;
use Authen::PAM qw(:constants);


### Start of Settings ###
my $SERVICE_NAME = 'jabberd';
my $DEBUG = 0;
### End of Settings #####



open(STDERR, ">/tmp/jabber-authpipe.log") or die "Failed to open log";



# Flush output immediately.
$| = 1;

# On startup, we have to inform c2s of the functions we can deal with.
print "OK USER-EXISTS CHECK-PASSWORD FREE\n";

# Our main loop
my $buf;
while(sysread (STDIN, $buf, 1024) > 0)
{
    my ($cmd, @args) = split ' ', $buf;
    $cmd =~ tr/[a-z]/[A-Z]/;
    $cmd =~ tr/_/-/;
    if ($cmd eq 'USER-EXISTS') {
    	print cmd_user_exists( @args ), "\n";
	} elsif ($cmd eq 'CHECK-PASSWORD') {
    	print cmd_check_password( @args ), "\n";
	} elsif ($cmd eq 'FREE') {
		# c2s shutting down, do the same.
		last;
	} else {
		print STDERR "Unsupported command: '$cmd'\n" if ($DEBUG);
		print "NO\n";
	}
}




# Determine if the requested user exists.
sub cmd_user_exists
{
    my ($user, $realm) = @_;

	my ($name,$passwd,$uid,$gid) = getpwnam($user);
	if (defined $name) {
		print STDERR "User '$user' exists with ID $uid.\n" if ($DEBUG);
		return "OK";
	} else {
		print STDERR "User '$user' does not exist.\n" if ($DEBUG);
		return 'NO';
	}
}


# Compare the given password with the stored password.
sub cmd_check_password
{
    my ($username, $encoded_pass, $realm) = @_;

	# Decode the password
	my $password = decode_base64($encoded_pass);
	return "NO" if not $password;
	
	my $handler = sub {
		my @response = ();
		
		while (@_) {
			my $code    = shift;
			my $message = shift;
			my $answer  = undef;
			
			if ( $code == PAM_PROMPT_ECHO_ON ) {
				$answer = $username;
			}
			
			if ( $code == PAM_PROMPT_ECHO_OFF ) {
				$answer = $password;
			}
			
			push( @response, PAM_SUCCESS, $answer );
		}
		
		return ( @response, PAM_SUCCESS );
	};
	
	
	my $pam = Authen::PAM->new( $SERVICE_NAME, $username, $handler );
	unless ( ref $pam ) {
		my $error = Authen::PAM->pam_strerror($pam);
		print STDERR "Failed to authenticate user '$username' using service '$SERVICE_NAME'. Reason: '$error'\n";
        return 'NO';
    }
    
    
	my $result = $pam->pam_authenticate;
	unless ( $result == PAM_SUCCESS ) {
		my $error = $pam->pam_strerror($result);
		print STDERR "Failed to authenticate user '$username' using service '$SERVICE_NAME'. Reason: '$error'\n";
        return 'NO';
    }

	$result = $pam->pam_acct_mgmt;
    unless ( $result == PAM_SUCCESS ) {
		my $error = $pam->pam_strerror($result);
		print STDERR "Failed to authenticate user '$username' using service '$SERVICE_NAME'. Reason: '$error'\n";
        return 'NO';
    }

	print STDERR "Successfully authenticated user '$username' using service '$SERVICE_NAME'.\n" if ($DEBUG);

	return 'OK';
}




__END__


=head1 NAME

jabberd-authpipe-pam - Allows Jabber authentication against PAM without running jabberd as root.

=head1 VERSION

This document describes version 0.1 of jabberd-authpipe-pam, released 25th December 2006.

=head1 DESCRIPTION

Configure jabberd2 by editing c2s.xml:

<module>pipe</module>

<pipe>
  <!-- Program to execute -->
  <exec>/usr/local/libexec/jabberd-authpipe-pam.pl</exec>
</pipe>

Place this script in /usr/local/libexec then run:
  chown root jabberd-authpipe-pam.pl
  chmod 4755 jabberd-authpipe-pam.pl

This sets the script to run as suid root and gives it access to the 
shadow password file. You man need to install perl-suid in order to 
run perl scripts with the suid bit set.

This script only implements the User-Exists and Check-Password routines.
See docs/dev/c2s-pipe-authenticator for details about the protocol.

To get this script to work with PSI, Ifound that I had to enable 
"Allow Plaintext Login" in PSI. Please make sure that you use SSL 
so that plain-text passwords aren't sent over the network.


=head1 README

This script allows Jabber authentication against PAM without running jabberd as root.

=head1 PREREQUISITES

This script requires the Jabberd 2.0 server.
It also requires the following other modules from CPAN: C<MIME-Base64> and C<Authen::PAM>.


=pod OSNAMES

Linux

=pod SCRIPT CATEGORIES

Misc

=head1 AUTHOR

Nicholas Humfrey E<lt>njh@aelius.comE<gt>

=head1 COPYRIGHT

    Copyright (c) 2006, Nicholas J Humfrey
    This code is hereby placed into the public domain.

=cut
