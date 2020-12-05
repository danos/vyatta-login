#!/usr/bin/perl

# **** License ****
#
# Copyright (c) 2018-2020, AT&T Intellectual Property.
#    All Rights Reserved.
#
# Copyright (c) 2014-2016, Brocade Communications Systems, Inc.
#    All Rights Reserved.
#
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2013 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Getopt::Long;
use Template;

my ( $routing, $system );

GetOptions( "routing:s" => \$routing, "system:s" => \$system  );

# This is just a simple wrapper that allows for extensiblility
# of login types.

my $config = new Vyatta::Config;

#
# Authentication chaining
#

my $local_pam_config = "/usr/share/pam-configs/vyatta-local";

# PAMConfigFrameworkSpec states priorty 512 for central network authentication
my $chain_priority_max = 512;

# the pam-auth-update priorty of the pam_unix module
my $chain_priority_unix = 256;

my %chain_prio = ();
my %enforce = ();
my $single_enforced_method = 0;

my $method_prio = $chain_priority_max;
my @chain = $config->returnValues("system login auth-chain method");

foreach my $method (@chain) {
        if ($method eq "local") {
            # if local method comes before remote ones, any following
            # method needs to have a lower prio, even if it's a remote method.
            $method_prio = $chain_priority_unix;
        }

        $chain_prio{$method} = --$method_prio;

        # if auth-chain consists only of one method
        # then authentication is enforced.
        # E.g. no local-login, if remote-AAA servers are reachable
        # E.g. no  remote-login, if local-only is (temp) configured in auth-chain
        if (scalar(@chain) == 1) {
            $enforce{$method} = 1;
            $single_enforced_method = 1;
            last;
        }
}

# When the auth-chain method is added/deleted from config,
# we need to check if tacplus servers are configured in a
# non-default VRF. If tacplus servers are configured in non-
# default, then the tacplusd and pam sssd is reloaded to 
# reflect the change in auth-chain config

if ( ($config->isChanged("system login auth-chain method")) && (!defined($routing)) ) {
    $routing = "routing";
} 

# Disable user account after N failed login attempts
my $n = $config->returnValue("system login auto-disable attempts");
my $t = $config->returnValue("system login auto-disable duration");
my $pam_dest = '/usr/share/pam-configs/vyatta-pam-tally';
if ( defined($n) && defined($t) ) {
    open(my $fh, '<', '/opt/vyatta/share/pam-configs/vyatta-pam-tally.template');
    my $template = Template->new();
    my %tree_in = ( 'PAM_TALLY_PARAMS' => "onerr=fail deny=$n unlock_time=$t" );
    $template->process( $fh, \%tree_in, $pam_dest)
        or die __FILE__ . ": Could not fill out vyatta-pam-tally\n";
    close($fh);
} else {
    unlink $pam_dest;
}

sub write_local_user_pam_config {
    open(my $fh, ">", $local_pam_config) or die("Failed to open $local_pam_config: $!\n");
    my $pri = $chain_prio{'local'} // --$method_prio;
    my $control = exists $enforce{'local'} ? "required" : "sufficient";

    print($fh qq(Name: Vyatta authentication for local system users
Default: yes
Priority: $pri
Account-Type: Additional
Account:
$control pam_localuser.so));

    close $fh;
}

#
# Authentication method setup
#

sub update_auth_method {
    my $path = shift;
    my %loginNodes = $config->listNodeStatus("$path");
    while ( my ($type, $status) = each %loginNodes) {
       # skip non login types
       next if ($type eq 'banner');
       next if ($type eq 'session-timeout');
       next if ($type eq 'group');
       next if ($type eq 'auth-chain');
       next if ($type eq 'max-sessions');
       next if ($type eq 'auto-disable');
       next if ($type eq 'user-isolation');

       # convert radius-server to RadiusServer
       my $kind = ucfirst $type;
       $kind =~ s/-server$/Server/;

       # method name
       my $method = $type;
       $method =~ s/-server$//;

       $chain_prio{$method} = --$method_prio
          unless($chain_prio{$method});

       my $cfg_status = $status;

       # disable method if another one got expliclty defined
       if ($single_enforced_method && (!defined($enforce{$method})
	       || !$enforce{$method})) {
          $status = "disable";
       }

       # Dynamically load the module to handle that login method
       my $module_name = "Vyatta/Login/$kind.pm";
       require $module_name;  ## no critic

       # Dynamically invoke update for this type
       my $login    = "Vyatta::Login::$kind";
       $login->update($status, $chain_prio{$method},
                      $enforce{$method}, $cfg_status);
    }
}
if ( defined $system ) {
    if ($config->exists("system login")) {
        update_auth_method("system login");
    }
}
if ( defined $routing ) {
    if ($config->exists("routing routing-instance")) {
        my @vrf = $config->listNodes("routing routing-instance");
        for my $vrf ( @vrf ) {
            # This is true when tacplus/radius config is added  
            if ($config->exists("routing routing-instance $vrf system login")) {
                update_auth_method("routing routing-instance $vrf system login");
            } elsif ($config->existsOrig("routing routing-instance $vrf system login")) { 
                # This is true when tacplus/radius config is deleted
                update_auth_method("routing routing-instance $vrf system login");
            }
        }
    }  elsif ($config->existsOrig("routing routing-instance")) {
        # This means the routing-instance is being deleted. So stop
        # everything under it.
        my @vrfd = $config->listOrigNodes("routing routing-instance");
        for my $vrfd ( @vrfd ) {
            if ($config->existsOrig("routing routing-instance $vrfd system login")) {
                update_auth_method("routing routing-instance $vrfd system login");
            }
        }
    }
}

# Must come after calling update_auth_method for the available methods
# to ensure that the method ordering is correct when there is no explicit
# auth-chain config (since remote auth methods are always preferred over
# the local method).
write_local_user_pam_config();

system("DEBIAN_FRONTEND=noninteractive pam-auth-update");
