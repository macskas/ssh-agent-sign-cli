#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use IO::Socket;
use bigint;
use Digest::SHA qw/sha1_hex/;
use Digest::MD5 qw/md5_hex/;
use Carp qw( croak );
use Getopt::Std;

use constant {
    SSH2_AGENTC_REQUEST_IDENTITIES => 11,
    SSH2_AGENT_IDENTITIES_ANSWER => 12,
    SSH2_AGENTC_SIGN_REQUEST => 13,
    SSH2_AGENT_SIGN_RESPONSE => 14,
    SSH_AGENT_FAILURE => 5
};

my $quiet = 0;
my $agent = {
    sock => 0
};

package MyBuffer;

sub new {
    my $class = shift;
    my $agent = bless {}, $class;
    $agent->init(@_);
    return $agent;
}

sub init {
    my $self = shift;
    my $length = shift;
    my $data = shift;
    $self->{'offset'} = 0;
    $self->{'length'} = $length;
    $self->{'data'} = $data;
}

sub get_bytes()
{
    my $self = shift;
    my $len = shift;

    my $ret = substr($self->{'data'}, $self->{'offset'}, $len);
    $self->{'offset'} += $len;

    return $ret;
}

sub get_all()
{
    my $self = shift;
    return $self->{'data'};
}

sub get_offset()
{
    my $self = shift;
    return $self->{'offset'};
}

sub set_offset()
{
    my $self = shift;
    my $offset = shift;
    $self->{'offset'} = $offset;
}

sub get_bytes_range()
{
    my $self = shift;
    my $offset = shift;
    my $len = shift;

    my $ret = substr($self->{'data'}, $offset, $len);

    return $ret;
}

sub get_int8()
{
    my $self = shift;
    my $r = $self->get_bytes(1);
    return unpack("c", $r);
}

sub get_int32()
{
    my $self = shift;
    my $r = $self->get_bytes(4);
    return unpack("N", $r);
}

sub put_int8()
{
    my $self = shift;
    my $num = shift;
    $self->{'length'} += 1;
    $self->{'data'} .= pack "c", $num;
}

sub put_int32()
{
    my $self = shift;
    my $num = shift;
    $self->{'length'} += 4;
    $self->{'data'} .= pack "N", $num;
}

sub put_bytes()
{
    my $self = shift;
    my $len = shift;
    my $buffer = shift;
    $self->{'data'} .= $buffer;
    $self->{'length'} += $len;
}


package main;

sub create_socket {
    my $agent = shift;
    my $authsock = $ENV{"SSH_AUTH_SOCK"} or return;

    $agent->{sock} = IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $authsock
    ) or die($!);
}

sub close_socket {
    my $agent = shift;
    close($agent->{sock}) or warn qq{Could not close socket: $!\n};
}

sub request {
    my $agent = shift;
    my $req = shift;

    my $len = pack "N", $req->{'length'};
    my $sock = $agent->{sock};
    (syswrite($sock, $len, 4) == 4 and
        syswrite($sock, $req->{'data'}, $req->{'length'}) == $req->{'length'}) or
        croak "Error writing to auth socket.";
    $len = 4;
    my $buf;
    while ($len > 0) {
        my $l = sysread $sock, $buf, $len;
        croak "Error reading response length from auth socket." unless $l > 0;
        $len -= $l;
    }
    $len = unpack "N", $buf;
    croak "Auth response too long: $len" if $len > 256 * 1024;

    $buf = "";
    my $rlen = 0;
    while ($rlen < $len) {
        my $b;
        my $l = sysread $sock, $b, $len;
        croak "Error reading response from auth socket." unless $l > 0;
        $buf = "$buf$b";
        $rlen += $l;
    }

    my $resp = MyBuffer->new($rlen, $buf);
    return $resp;
}

sub expmod {
    my($a, $b, $n) = @_;
    my $c = 1;
    do {
        ($c *= $a) %= $n if $b % 2;
        ($a *= $a) %= $n;
    } while ($b = int $b/2);
    return $c;
}

sub sreq()
{
    my $length = shift || 0;
    my $data = shift;
    if ($length == 0) {
        $length = length($data);
    }
    return {
        'length' => $length,
        'data' => $data
    };
}

&create_socket($agent);

sub get_key()
{
    my $resp = shift;
    my $key_size = $resp->get_int32();

    my $key_start = $resp->get_offset();
    my $key_type_size = $resp->get_int32();
    my $key_type = $resp->get_bytes($key_type_size);
    my $dsa_key = $resp->get_bytes($key_size - $key_type_size - 4);
    my $key_end = $resp->get_offset();
    my $comment_size = $resp->get_int32();
    my $comment = $resp->get_bytes($comment_size);
    my $key_full = $resp->get_bytes_range($key_start, $key_end-$key_start);

    my $r = {
        "key_full_size" => $key_end-$key_start,
        "key_full" => $key_full,
        "comment" => $comment,
        "key" => $dsa_key,
        "key_type" => $key_type,
        "fingerprint" => md5_hex($key_full)
    };

    return $r;
}

sub key_extract()
{
    my $in = shift;
    my $r = MyBuffer->new(length($in), $in);
    my $public_exponent_size = $r->get_int32();
    my $public_exponent = $r->get_bytes($public_exponent_size);
    my $modulus_size = $r->get_int32();
    my $pq = $r->get_bytes($modulus_size);
    my $ret = {
        'public_exponent_size' => $public_exponent_size,
        'public_exponent' => $public_exponent,
        'modulus_size' => $modulus_size,
        'pq' => $pq
    };
    return $ret;
}

sub sign_message()
{
    my $message = shift;
    my $key = shift;
    my $ke = &key_extract($key->{'key'});
    my $r = MyBuffer->new(0, "");
    my $message_size = length($message);

    $r->put_int8(SSH2_AGENTC_SIGN_REQUEST);
    $r->put_int32($key->{'key_full_size'});
    $r->put_bytes($key->{'key_full_size'}, $key->{'key_full'});
    $r->put_int32($message_size);
    $r->put_bytes($message_size, $message);
    $r->put_int32(0); # flags
    my $sock = $agent->{'sock'};
    my $all = $r->get_all();

    my $req = &sreq(length($all), $all);
    my $resp = &request($agent, $req);
    my $message_type = $resp->get_int8();
    if ($message_type == SSH2_AGENT_SIGN_RESPONSE) {
        my $signature_size = $resp->get_int32();
        my $key_type_size = $resp->get_int32();
        my $key_type = $resp->get_bytes($key_type_size);
        my $signed_value_size = $resp->get_int32();
        my $signed_value = $resp->get_bytes($signed_value_size);
        my $signed_value_hex = unpack("H*", $signed_value);
#        if (&verify_key($message, $signed_value_hex, $ke->{'public_exponent'}, $ke->{'pq'})) {
#            print "VERIFY: OK\n";
 #       }
        return $signed_value_hex;
    }
}

sub verify_key()
{
    my ($message, $signed_value_hex, $public_exponent, $modulus) = @_;
    my $modulus_hex = unpack("H*", $modulus);
    my $public_exponent_hex = unpack("H*", $public_exponent);

    my $emod = &expmod(hex($signed_value_hex), hex($public_exponent_hex), hex($modulus_hex));
    my $decoded_hex = substr($emod->as_hex, 2);
    my $sha1_signed = substr($decoded_hex, -40);
    my $sha1_message = sha1_hex($message);
    if ($sha1_signed eq $sha1_message) {
        return 1;
    }
    return 0;
}

sub get_keys()
{
    my @keys = ();
    my $req = &sreq(1, chr(SSH2_AGENTC_REQUEST_IDENTITIES));
    my $resp = &request($agent, $req);
    if ($resp->get_int8() == SSH2_AGENT_IDENTITIES_ANSWER) {
        my $num_keys = $resp->get_int32();
        for (my $i=0; $i<$num_keys; $i++) {
            my $key = &get_key($resp);
            push(@keys, $key);
        }
    }
    return @keys;
}

sub do_error()
{
    my $msg = shift;
    if (!$quiet) {
        print STDERR sprintf("[$0] %s ERROR > %s\n", scalar localtime, $msg);
    }
    exit(1);
}

sub do_help()
{
    print "$0 -m <message> | -l\n";
    print "   -q                 - quiet mode\n";
    print "   -m <message>       - message to sign\n";
    print "   -c <comment>       - filter by ssh-key *comment*\n";
    print "   -f <hash>          - filter by ssh-key =fingerprint\n";
    print "   -x <comment>       - exclude by ssh-key *comment*\n";
    print "   -l                 - list keys\n";
    exit(1);
}

sub main()
{
    my $gopt = {};
    getopts("qm:c:f:x:hl", $gopt);

    if (defined($gopt->{'h'})) {
        &do_help();
    }

    if (defined($gopt->{'q'})) {
        $quiet = 1;
    }

    my $mode = "sign";

    if (defined($gopt->{'l'})) {
        $mode = "list";
    }

    if ($mode eq 'sign') {
        if (!defined($gopt->{'m'})) {
            &do_help();
        }
    }


    if (!defined($ENV{SSH_AUTH_SOCK})) {
        &do_error("No ssh auth socket. Exiting.");
    }

    my $message = defined($gopt->{'m'}) ? $gopt->{'m'} : 0;
    my $filter_fingerprint = defined($gopt->{'f'}) ? lc($gopt->{'f'}) : 0;
    if ($filter_fingerprint) {
        $filter_fingerprint =~ s/[^a-fA-F0-9]//g;
        if (!$filter_fingerprint || length($filter_fingerprint) != 32) {
            &do_error("Invalid fingerprint input.");
        }
    }
    my $include_comment = defined($gopt->{'c'}) ? lc($gopt->{'c'}) : 0;
    my $exclude_comment = defined($gopt->{'x'}) ? lc($gopt->{'x'}) : 0;

    &create_socket($agent);
    my @keys = &get_keys();
    my @final_keys = ();
    foreach my $key (@keys) {
        if ($include_comment) {
            if (index(lc($key->{'comment'}), $include_comment) == -1) {
                next;
            }
        }
        if ($exclude_comment) {
            if (index(lc($key->{'comment'}), $exclude_comment) != -1) {
                next;
            }
        }

        if ($filter_fingerprint) {
            if ($key->{'fingerprint'} ne $filter_fingerprint) {
                next;
            }
        }
        push(@final_keys, $key);
    }
    if (scalar @final_keys == 0) {
        &do_error("No keys found.");
    }
    foreach my $key (@final_keys) {
        if ($mode eq 'list') {
            printf("%s:%s\n", $key->{'fingerprint'}, $key->{'comment'});
        } else {
            my $signed_value_hex = &sign_message($message, $key);
            printf("%s:%s\n", $key->{'fingerprint'}, $signed_value_hex);
        }
    }
    &close_socket($agent);
}

&main();
