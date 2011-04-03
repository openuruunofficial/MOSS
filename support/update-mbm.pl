#!/usr/bin/env perl

# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2008  a'moaca'
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;

if ($#ARGV != 1) {
    die "Usage: $0 <.mbm file> <uncompressed file to update>\n";
}

sub main {
    open(MBM, "+<$ARGV[0]") or die "Error opening $ARGV[0]: $!\n";
    my $file = $ARGV[1];
    $file =~ s/\//\\/g;
    $file .= ".gz";

    # scan file to find offset
    my ($buf, $entries, @offsets, $offset, $i, $len);

    sysread(MBM, $buf, 4) or die "Truncated .mbm file\n";
    $entries = unpack("L", $buf);

    $offset = 4;
    for ($i = 0; $i < $entries; $i++) {
	sysread(MBM, $buf, 4) or die "Truncated .mbm file\n";
	$len = unpack("L", $buf);
	sysread(MBM, $buf, $len) or die "Truncated .mbm file\n";

	# we have the whole entry in $buf
	my ($str, $idx) = get_widestring($buf, 0);
	if ($idx < 0) {
	    die "Bad file format at offset $offset\n";
	}
	($str, $idx) = get_widestring($buf, $idx);
	if ($idx < 0) {
	    die "Bad file format at offset $offset\n";
	}
	if ($str eq $file) {
	    # it's an exact match
	    @offsets = ( [$str, $offset] );
	    last;
	}
	else {
	    $idx = index($str, $file);
	    if ($idx < 0) {
		# not a substring
	    }
	    elsif ($idx + length($file) != length($str)) {
		# this means that $file is found in $str but not at the end
	    }
	    else {
		push(@offsets, [$str, $offset]);
	    }
	}

	$offset += 4+$len;
    }

    if (!@offsets) {
	die "Could not find $ARGV[1] in the manifest\n";
    }
    my @tuple = @{$offsets[0]};
    if (($#offsets == 0) && ($tuple[0] eq $file)) {
	# exact match
	$offset = $tuple[1];
    }
    else {
	# multiple or imprecise matches
	$offset = 0;
	print("No exact match found\n");
	foreach my $aref (@offsets) {
	    @tuple = @$aref;
	    print("Did you mean $tuple[0] ? ");
	    my $input = <STDIN>;
	    if ($input =~ /^\s*y/i) {
		$offset = $tuple[1];
		last;
	    }
	}
	if ($offset == 0) {
	    die "Could not find $ARGV[1] in the manifest\n";
	}
    }

    # now compute checksums and lengths for the file
    my ($size, $sum) = get_data($ARGV[1]);
    `gzip $ARGV[1]`;
    my ($zsize, $zsum) = get_data($ARGV[1].".gz");
    print("Updating manifest for $ARGV[1]...\n");
    print("\tuncompressed $sum ($size)\n\t  compressed $zsum ($zsize)\n");

    # now write to the manifest file
    seek(MBM, $offset, 0);
    sysread(MBM, $buf, 4);
    $len = unpack("L", $buf);
    sysread(MBM, $buf, $len);
    my ($str, $idx) = get_widestring($buf, 0);
    ($str, $idx) = get_widestring($buf, $idx);
    # $idx is the start of the first checksum
    seek(MBM, $offset+4+$idx, 0);
    for ($i = 0; $i < 32; $i++) {
	syswrite(MBM, $sum, 1, $i);
	seek(MBM, 1, 1);
    }
    seek(MBM, 2, 1);
    for ($i = 0; $i < 32; $i++) {
	syswrite(MBM, $zsum, 1, $i);
	seek(MBM, 1, 1);
    }
    seek(MBM, 2, 1);
    my $next = pack("CCCCS",
		    ($size & 0x00FF0000) >> 16,
		    ($size & 0xFF000000) >> 24,
		    ($size & 0xFF),
		    ($size & 0x0000FF00) >> 8,
		    0);
    syswrite(MBM, $next, 6);
    $next = pack("CCCCS",
		    ($zsize & 0x00FF0000) >> 16,
		    ($zsize & 0xFF000000) >> 24,
		    ($zsize & 0xFF),
		    ($zsize & 0x0000FF00) >> 8,
		    0);
    syswrite(MBM, $next, 6);

    # done
    close(MBM);
}

sub get_widestring {
    my ($buf, $idx) = @_;

    my $str = "";
    my $i = 0;
    while ($idx+$i < length($buf)) {
	my $char = substr($buf, $idx+$i, 1);
	$i += 2;
	if (ord($char) == 0) {
	    return ($str, $idx+$i);
	}
	else {
	    $str .= $char;
	}
    }
    return ("", -1);
}

sub get_data {
    my $f = shift;

    my @s = stat($f);
    if (!@s) {
	die "Could not stat $f\n";
    }
    my $sum = `md5sum $f`;
    if (!$sum) {
	$sum = `md5 $f`;
    }
    if (!$sum) {
	die "Could not compute MD5 checksum of $f\n";
    }
    chomp($sum);
    # stupid differences between Linux and BSD
    $sum =~ s/^.*(\w{32}).*$/$1/;
    return ($s[7], $sum);
}

main();
