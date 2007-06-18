#!/usr/bin/perl -w

#
# Sample pipe authenticator module. You can use this as a basis for your
# own auth/reg module. See docs/dev/c2s-pipe-authenticator for details
# about the protocol.
#
# This code is hereby placed into the public domain.
#

use strict;

use MIME::Base64;

# Flush output immediately.
$| = 1;

# On startup, we have to inform c2s of the functions we can deal with. USER-EXISTS is not optional.
print "OK USER-EXISTS GET-PASSWORD CHECK-PASSWORD SET-PASSWORD CREATE-USER DESTROY-USER FREE\n";

# Our main loop
my $buf;
while(sysread (STDIN, $buf, 1024) > 0)
{
    my ($cmd, @args) = split ' ', $buf;
    $cmd =~ tr/[A-Z]/[a-z]/;
    $cmd =~ tr/-/_/;

    eval "print _cmd_$cmd(\@args), '\n'";
}

# Determine if the requested user exists.
sub _cmd_user_exists
{
    my ($user, $realm) = @_;

    # !!! return "OK" if user exists;

    return "NO";
}

# Retrieve the user's password.
sub _cmd_get_password
{
    my ($user, $realm) = @_;

    # !!! $pass = [password in database];
    #     return "NO" if not $pass;
    #     $encoded_pass = encode_base64($pass);
    #     return "OK $encoded_pass" if $encoded_pass;

    return "NO";
}

# Compare the given password with the stored password.
sub _cmd_check_password
{
    my ($user, $encoded_pass, $realm) = @_;

    # !!! $pass = decode_base64($encoded_pass);
    #     return "NO" if not $pass;
    #     $spass = [password in database];
    #     return "OK" if $pass eq $spass;

    return "NO";
}

# Store the password in the database.
sub _cmd_set_password
{
    my ($user, $encoded_pass, $realm) = @_;

    # !!! $pass = decode_base64($encoded_pass);
    #     return "NO" if not $pass;
    #     $fail = [store $pass in database];
    #     return "OK" if not $fail;

    return "NO";
}

# Create a user in the database (with no auth credentials).
sub _cmd_create_user
{
    my ($user, $realm) = @_;

    # !!! $fail = [create user in database]
    #     return "OK" if not $fail;

    return "NO";
}

# Delete a user and associated credentials.
sub _cmd_delete_user
{
    my ($user, $realm) = @_;

    # !!! $fail = [delete user in database]
    #     return "OK" if not $fail;

    return "NO";
}

# c2s shutting down, do the same.
sub _cmd_free
{
    # !!! free data
    #     close database handles

    exit(0);
}
