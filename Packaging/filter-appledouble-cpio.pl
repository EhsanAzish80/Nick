#!/usr/bin/perl

use strict;
use warnings;

@ARGV == 2 or die "Usage: $0 INPUT.cpio OUTPUT.cpio\n";
my ($input_path, $output_path) = @ARGV;

open my $input, '<:raw', $input_path or die "Cannot open $input_path: $!\n";
open my $output, '>:raw', $output_path or die "Cannot open $output_path: $!\n";
my $written = 0;
my %inode_map;
my $next_inode = 0;

sub read_exact {
    my ($handle, $length) = @_;
    my $buffer = '';
    while (length($buffer) < $length) {
        my $count = read($handle, my $chunk, $length - length($buffer));
        defined $count or die "Failed reading cpio archive: $!\n";
        $count > 0 or die "Unexpected end of cpio archive\n";
        $buffer .= $chunk;
    }
    return $buffer;
}

while (1) {
    my $header = read_exact($input, 76);
    substr($header, 0, 6) eq '070707'
        or die "Unsupported cpio format (expected portable ASCII odc)\n";

    my $name_size = oct(substr($header, 59, 6));
    my $file_size = oct(substr($header, 65, 11));
    my $name_field = read_exact($input, $name_size);
    my $data = read_exact($input, $file_size);
    (my $name = $name_field) =~ s/\0\z//;

    my $is_appledouble = $name =~ m{(?:^|/)\._[^/]*$};
    if (!$is_appledouble) {
        my $inode_key = substr($header, 6, 12);
        if (!exists $inode_map{$inode_key}) {
            $inode_map{$inode_key} = $next_inode++;
        }
        substr($header, 6, 6) = '000000';
        substr($header, 12, 6) = sprintf('%06o', $inode_map{$inode_key});
        print {$output} $header, $name_field, $data
            or die "Failed writing filtered cpio archive: $!\n";
        $written += length($header) + length($name_field) + length($data);
    }

    last if $name eq 'TRAILER!!!';
}

my $block_padding = (512 - ($written % 512)) % 512;
print {$output} "\0" x $block_padding
    or die "Failed writing cpio block padding: $!\n";

close $input or die "Failed closing $input_path: $!\n";
close $output or die "Failed closing $output_path: $!\n";
