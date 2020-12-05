#!/usr/bin/perl
#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2009-2015, Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;
use warnings;

use lib '/opt/vyatta/share/perl5/';
use Vyatta::Config;

use Getopt::Long;
use File::Copy;
use File::Compare;

my $os_release_file    = '/etc/os-release';
my $prelogin_file      = '/etc/issue';
my $prelogin_net_file  = '/etc/issue.net';
my $prelogin_ssh_file  = '/etc/issue.ssh';
my $postlogin_file     = '/run/motd.vyatta';

sub save_orig_file {
    my $file = shift;

    move($file, "$file.old") if ! -e "$file.old";
    return;
}

sub restore_orig_file {
    my $file = shift;

    move("$file.old", $file)if -e "$file.old";
    return;
}

sub is_same_as_file {
    my ($file, $value) = @_;

    return if ! -e $file;

    my $mem_file = ' ';
    open my $MF, '+<', \$mem_file or die "couldn't open memfile $!\n";
    print $MF $value;
    seek($MF, 0, 0);

    my $rc = compare($file, $MF);
    return 1 if $rc == 0;
    return;
}

sub write_file_value {
    my ($file, $value) = @_;

    # Avoid unnecessary writes.  At boot the file will be the
    # regenerated with the same content.
    return if is_same_as_file($file, $value);

    open my $F, '>', $file or die "Error: opening $file [$!]";
    print $F "$value";
    close $F;
}

sub get_banner {
    my $banner_type = shift;

    my $config = new Vyatta::Config;
    $config->setLevel('system login banner');
    my $text = $config->returnValue($banner_type);
    $text =~ s|\\n|\n|g;
    $text =~ s|\\t|\t|g;
    return $text;
}

sub get_os_release_field {
    my $key = shift;

    open( my $fh, '<', $os_release_file )
      or die "Error opening $os_release_file [$!]";

    while ( my $line = <$fh> ) {
        if ( $line =~ /\s*$key\s*=\s*[\"']?([^\"']+)[\"']?/ ) {
            close($fh);
            return $1;
        }
    }
    close($fh);
    return;
}

sub perform_os_release_escapes {
    my ( $source, $dest ) = @_;

    open( my $source_fh, '<', $source ) or die "Error opening $source [$!]";
    read( $source_fh, my $text, -s $source_fh );
    close($source_fh);

    my @escapes = ( $text =~ /\\S\{(\w+)\}/g );
    for my $key (@escapes) {
        my $field = get_os_release_field($key);
        $text =~ s/\\S\{$key\}/$field/g;
    }

    if ( $text !~ /\n\z/ ) {
        $text .= "\n\n";
    }

    write_file_value( $dest, $text );
}

sub generate_prelogin_ssh_file {
    perform_os_release_escapes( $prelogin_net_file, $prelogin_ssh_file );
    chmod( 0644, $prelogin_ssh_file );
}

sub add_prelogin {
    save_orig_file($prelogin_file);
    save_orig_file($prelogin_net_file);
    my $text = get_banner('pre-login');
    write_file_value($prelogin_file, $text);
    write_file_value($prelogin_net_file, $text);
    return;
}

sub add_postlogin {
    my $text = get_banner('post-login');
    write_file_value($postlogin_file, $text);
    return;
}


#
# main
#
my ($action, $banner_type);

GetOptions("action=s"      => \$action,
	   "banner-type=s" => \$banner_type,
);

die "Error: no action"      if ! defined $action;
die "Error: no banner-type"
  if ( ( !defined $banner_type )
    && ( $action ne 'generate-ssh' ) );

if ($action eq 'update') {
    if ($banner_type eq 'pre-login') {
	add_prelogin();
    generate_prelogin_ssh_file();
	exit 0;
    }
    if ($banner_type eq 'post-login') {
	add_postlogin();
	exit 0;
    }
}

if ($action eq 'delete') {
    if ($banner_type eq 'pre-login') {
	restore_orig_file($prelogin_file);
	restore_orig_file($prelogin_net_file);
    generate_prelogin_ssh_file();
	exit 0;
    }
    if ($banner_type eq 'post-login') {
        unlink($postlogin_file);
	exit 0;
    }
}

if ( $action eq 'generate-ssh' ) {
    generate_prelogin_ssh_file();
    exit 0;
}

exit 1;

#end of file
