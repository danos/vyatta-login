#!/usr/bin/perl

# **** License ****
#
# Copyright (c) 2018-2020 AT&T Intellectual Property.
#   All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
#
# **** End License ****

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Configd;
use Vyatta::Login::Password;
use File::Slurp qw(read_file);
use Template;
use IPC::Run3;
use JSON;

my $configd = Vyatta::Configd::Client->new();
my $db      = $Vyatta::Configd::Client::AUTO;

my $ptemplate = '/opt/vyatta/etc/security/pwquality.config.template';
my $pcfg      = '/etc/security/pwquality.conf';

sub get_pass_req {
    return unless $configd->node_exists( $db, "system password requirements" );
    return $configd->tree_get_hash("system password requirements");
}

sub get_login_users {
    return unless $configd->node_exists( $db, "system login user" );
    return $configd->tree_get_hash("system login user");
}

sub update_pwquality {
    my ($req) = (@_);
    return unless defined $req;
    my %tree_in = %$req;
    $tree_in{'requirements'}{'disable-gecos-check'} = 1
      if exists $tree_in{'requirements'}{'disable-gecos-check'};
    $tree_in{'requirements'}{'disable-gecos-check'} = 1
      if exists $tree_in{'requirements'}{'user-match'};

    my $template = Template->new();
    open( my $fh, '<', $ptemplate );
    $template->process( $fh, \%tree_in, $pcfg )
      or die __FILE__ . ": Could not fill out pwquality template\n";
    close($fh);
}

sub update_history {
    my $req     = shift;

    my $r = undef;
    if ( defined($req) ) {
        my %tree_in = %$req;
        $r = $tree_in{'requirements'}{'history'}{'forbid-previous'};
    }

    if ( defined($r) ) {
        my $opwds = {};
        if ( -e $opwdFile ) {
            $opwds = decode_json( read_file($opwdFile) );
            die "Failed getting old passwords." unless defined($opwds);
            while ( my ( $u, $pwd ) = each %{$opwds} ) {
                if ( $pwd->{'count'} > $r ) {

                    # Remove extra old passwords
                    if ( $pwd->{'count'} > $r ) {
                        shift( @{ $pwd->{'old-passwords'} } )
                          while ( $pwd->{'count'}-- > $r );
                        $pwd->{'count'} = $r;
                    }
                }
            }
        }
        else {
            my $users = get_login_users();
            foreach my $user ( @{ $users->{'user'} } ) {
                my $pwd = $user->{'authentication'}->{'encrypted-password'};
                next unless ($pwd);
                my %opwd = ( 'count' => 1, 'old-passwords' => [$pwd] );
                $opwds->{$user->{'tagnode'}} = \%opwd;
            }
        }
        update_opasswd_file($opwds);
    } else {
        unlink $opwdFile;
    }
    return;
}

sub update_expiration {
    my $req     = shift;

    my $m = 99999;
    if ( defined($req) ) {
        my %tree_in = %$req;
        $m = $tree_in{'requirements'}{'expiration'}{'maximum-days'};
        $m = 99999 if !defined($m);
    }

    # Expiration on new user accounts
    my @cmd = (
        'sed',                                         '-i',
        qq{/#/!s/PASS_MAX_DAYS.*/PASS_MAX_DAYS   $m/}, '/etc/login.defs'
    );
    run3( \@cmd, \undef, undef, undef );

    # Update expiration for existing user accounts
    my $users = get_login_users();
    foreach my $user ( @{ $users->{'user'} } ) {
        my $pwd = $user->{'authentication'}->{'encrypted-password'};
        $m = 99999 unless ($pwd);
        my @cmd = ( 'chage', '-M', $m, $user->{'tagnode'} );
        run3( \@cmd, \undef, undef, undef );
    }
    return;
}

my $req = get_pass_req();
update_pwquality($req);
update_history($req);
update_expiration($req);
