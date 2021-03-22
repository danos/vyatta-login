# **** License ****
#
# Copyright (c) 2020 AT&T Intellectual Property.
#    All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****

package Vyatta::Login::Password;

use base qw(Exporter);

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Configd;

use File::Temp qw/ tempfile  tempdir /;
use File::Slurp qw(read_file);
use Template;
use JSON;

our @EXPORT_OK =
  qw(update_history save_old_password delete_user_from_opwdfile is_old_password);

my $opwdDir  = "/etc/vyatta/login";
my $opwdFile = "$opwdDir/opasswd.vyatta.json";

my $pamdPasswdFile = '/etc/pam.d/passwd';
my $pamdLoginFile  = '/etc/pam.d/login';

sub update_opasswd_file {
    my $opwds = shift;

    my ( $fh, $filename ) = tempfile( DIR => $opwdDir );
    chmod( 0600, $fh );
    print $fh encode_json($opwds);
    close($fh);
    rename( $filename, $opwdFile );
    return;
}

sub update_history {
    my $req     = shift;
    my %tree_in = %$req;

    my $r = $tree_in{'requirements'}{'history'}{'forbid-previous'};
    if ( !defined($r) ) {
        unlink $opwdFile;
        return;
    }

    die "Failed creating $opwdDir directory."
      unless ( -e $opwdDir or mkdir( $opwdDir, 0700 ) );

    my $opwds = {};
    if ( -e $opwdFile ) {
        $opwds = decode_json( read_file($opwdFile) );
        die "Failed getting old passwords." unless defined($opwds);
        while ( my ( $u, $pwd ) = each %{$opwds} ) {
            if ( $pwd->{'count'} > $r ) {

                # Remove extra old passwords
                shift( @{ $pwd->{'old-passwords'} } )
                  while ( $pwd->{'count'}-- > $r );
                $pwd->{'count'} = $r;
            }
        }
    }
    update_opasswd_file($opwds);
    return;
}

sub save_old_password {
    my ( $user, $pwd, $hist ) = @_;
    return unless ( defined($user) && defined($pwd) && defined($hist) );

    my $r = $hist->{'history'}->{'forbid-previous'};
    return if !defined($r);

    return unless ( -e $opwdFile );
    my $opwds = decode_json( read_file($opwdFile) );
    return if !defined($opwds);

    if ( exists $opwds->{$user} ) {
        shift( @{ $opwds->{$user}->{'old-passwords'} } )
          if ( $opwds->{$user}->{'count'} >= $r );
        push( @{ $opwds->{$user}->{'old-passwords'} }, $pwd );
        $opwds->{$user}->{'count'} += 1;
    }
    else {
        my %opwd = ( 'count' => 1, 'old-passwords' => [$pwd] );
        $opwds->{$user} = \%opwd;
    }
    update_opasswd_file($opwds);
    return;
}

sub delete_user_from_opwdfile {
    my $user = shift;
    return unless defined($user);

    return unless ( -e $opwdFile );
    my $opwds = decode_json( read_file($opwdFile) );
    return if !defined($opwds);
    delete $opwds->{$user} if exists $opwds->{$user};
    update_opasswd_file($opwds);
    return;
}

sub is_old_password {
    my ( $user, $pwd ) = @_;

    return 0 unless ( -e $opwdFile );
    my $opwds = decode_json( read_file($opwdFile) );
    return 0 unless defined($opwds);
    if ( exists $opwds->{$user} ) {
        foreach my $opwd ( @{ $opwds->{$user}->{'old-passwords'} } ) {
            my $npwd = crypt( $pwd, $opwd );
            return 1 if ( $npwd && $npwd eq $opwd );
        }
    }
    return 0;
}

1;
