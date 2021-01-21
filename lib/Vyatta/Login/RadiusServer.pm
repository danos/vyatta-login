# **** License ****
#
# Copyright (c) 2017-2021 AT&T Intellectual Property.
#    All Rights Reserved.
# Copyright (c) 2014, 2016 Brocade Communications Systems, Inc.
#    All Rights Reserved.
#
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****

package Vyatta::Login::RadiusServer;
use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use File::Compare;
use File::Copy;
use Module::Load::Conditional qw[can_load];
use IPC::Run3;
use Sys::Syslog;

my $vrf_available = can_load( modules => { "Vyatta::VrfManager" => undef }, 
        autoload => "true" );

my $PAM_RAD_CFG = '/etc/pam_radius_auth.conf';
my $PAM_RAD_TMP = "/tmp/pam_radius_auth.$$";

my $PAM_RAD_AUTH = "/usr/share/pam-configs/radius";
my $PAM_RAD_SYSCONF = "/opt/vyatta/etc/pam_radius.cfg";

my $RAD_DEF_CFG = "system login radius-server";
my $BASE_VRF_CFG = "routing routing-instance";

sub remove_pam_radius {
    $ENV{"DEBIAN_FRONTEND"} = "noninteractive";
    my @cmd = ("pam-auth-update", "-package", "--remove", "radius");
    die "pam-auth-update remove failed"
      unless run3( \@cmd, \undef, undef, undef );
    delete $ENV{"DEBIAN_FRONTEND"};

    unlink($PAM_RAD_AUTH)
	or die "Can't remove $PAM_RAD_AUTH";
}

sub add_pam_radius {
    copy($PAM_RAD_SYSCONF,$PAM_RAD_AUTH)
	or die "Can't copy $PAM_RAD_SYSCONF to $PAM_RAD_AUTH";

    $ENV{"DEBIAN_FRONTEND"} = "noninteractive";
    my @cmd = ("pam-auth-update", "-package", "radius");
    die "pam-auth-update add failed"
      unless run3( \@cmd, \undef, undef, undef );
    delete $ENV{"DEBIAN_FRONTEND"};
}

sub update {
    my ($this, $status, $chain_prio, $enforce) = @_;
    my $rconfig = new Vyatta::Config;
    my %servers;
    my $upstream_vrf = ( !-e "/proc/self/rtg_domain" );
    my $vrfId = $upstream_vrf ? '' : '1';

    if (($status eq "added") || ($status eq "changed") || ($status eq "static")) {
        if ( $rconfig->exists($RAD_DEF_CFG) ) {
            $rconfig->setLevel($RAD_DEF_CFG);
        } elsif ( $rconfig->exists($BASE_VRF_CFG) && $vrf_available ) {
            my @vrfList = $rconfig->listNodes($BASE_VRF_CFG);
            foreach my $vrf (@vrfList) {
                if ( $rconfig->exists(
                        "$BASE_VRF_CFG $vrf $RAD_DEF_CFG") ) {
                    $rconfig->setLevel(
                        "$BASE_VRF_CFG $vrf $RAD_DEF_CFG");
                    $vrfId =
                      $upstream_vrf
                      ? "vrf$vrf"
                      : Vyatta::VrfManager::get_vrf_id($vrf);
                }
            }
        }
        %servers = $rconfig->listNodeStatus();
    }
    my $count   = 0;

    open (my $cfg, ">", $PAM_RAD_TMP)
	or die "Can't open config tmp: $PAM_RAD_TMP :$!";

    print $cfg "# RADIUS configuration file\n";
    print $cfg "# automatically generated do not edit\n";
    print $cfg "# Server\tSecret\tTimeout\tSrcIP\tVrfId\n";

    if ( (my $size = keys %servers) != 0 ) {
        for my $server ( sort keys %servers ) {
	        next if ( $servers{$server} eq 'deleted' );
	        my $port    = $rconfig->returnValue("$server port");
	        my $secret  = $rconfig->returnValue("$server secret");
	        my $timeout = $rconfig->returnValue("$server timeout");
	        # in version 1.4 there's a new parameter, source_ip
	        my $src_ip = "";
	        my @cmd = ("dpkg-query", "-W", "-f=\${Version}", "libpam-radius-auth");
	        my $stdout;
	        run3( \@cmd, \undef, \$stdout, \undef );
	        if ( $? == 0 ) {
	            @cmd = ("dpkg", "--compare-versions", "$stdout", "ge", "1.4");
	            run3( \@cmd, \undef, undef, undef);
	            if ( $? == 0 ) {
	                $src_ip = "0";
	            }
	        }
	        print $cfg "$server:$port\t$secret\t$timeout\t$src_ip\t$vrfId\n";
	        ++$count;
        }
    }
    close($cfg);

    if ( compare( $PAM_RAD_CFG, $PAM_RAD_TMP ) != 0 ) {
        my $deprecated_msg =
"RADIUS support is deprecated and will be removed in a future release";
        syslog( "warning", $deprecated_msg );
        print( $deprecated_msg . "\n" );

        copy( $PAM_RAD_TMP, $PAM_RAD_CFG )
          or die "Copy of $PAM_RAD_TMP to $PAM_RAD_CFG failed";
    }
    unlink($PAM_RAD_TMP);

    if ( ($count > 0) && ($status ne "disable") ) {
        add_pam_radius();
    } else {
        remove_pam_radius();
    }
}

1;
