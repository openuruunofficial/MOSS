#!/usr/bin/env perl

# MOSS - A server for the Myst Online: Uru Live client/protocol
# Copyright (C) 2008-2009  a'moaca'
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

if ($#ARGV != 0) {
    die "Usage: $0 <.txt file>\n";
}

open(INF, "<$ARGV[0]");
$outname = $ARGV[0];
$outname =~ s/.txt/.mbam/;
open(OUTF, ">$outname");
while (<INF>) {
    chomp;
    next if /^#/;               # skip comments
    next unless /\S/;           # and blank lines
    $fname = $_;
    $fname =~ s/\\/\//g;
    ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
     $atime,$mtime,$ctime,$blksize,$blocks)
      = stat($fname);
    $sizeval = $size + 0;
    $strlen = length($fname);
    $zero = pack("C", 0);
    for ($i = 0; $i < $strlen; $i++) {
	syswrite(OUTF, $_, 1, $i);
	syswrite(OUTF, $zero, 1);
    }
    $next = pack("SCCCCS",
		 0,
		 ($sizeval & 0x00FF0000) >> 16,
		 ($sizeval & 0xFF000000) >> 24,
		 ($sizeval & 0xFF),
		 ($sizeval & 0x0000FF00) >> 8,
		 0);
    syswrite(OUTF, $next, 8);
}
close(INF);
close(OUTF);
