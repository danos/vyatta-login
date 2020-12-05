#!/usr/bin/perl

# **** License ****
#
# Copyright (c) 2018-2019 AT&T Intellectual Property.
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
use Template;

my $configd = Vyatta::Configd::Client->new();
my $db      = $Vyatta::Configd::Client::AUTO;

my $ptemplate = '/opt/vyatta/etc/security/pwquality.config.template';
my $pcfg      = '/etc/security/pwquality.conf';

sub get_pass_req {
    return unless $configd->node_exists( $db, "system password requirements" );
    return $configd->tree_get_hash("system password requirements");
}

sub update_pwquality {
    my ($req) = (@_);
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

my $req = get_pass_req();
exit unless defined $req;
update_pwquality($req);
