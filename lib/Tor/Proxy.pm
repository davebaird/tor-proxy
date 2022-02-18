package Tor::Proxy ;

# ideas stolen from LWP::UserAgent::Tor and TaskPipe::TorManager

# https://gitweb.torproject.org/torspec.git/tree/control-spec.txt

use v5.24 ;    # for postfix dereferencing
use warnings ;
use Carp ;
use Data::Dumper ;

use File::Which qw(which) ;
use IO::Socket::INET ;

use Net::EmptyPort qw(empty_port) ;
use Proc::Background ;
use Path::Tiny ;
use Feature::Compat::Try ;

use Types::Standard qw( Str Int Bool HashRef ArrayRef Maybe InstanceOf ) ;
use Moo ;
use MooX::ClassAttribute ;

use namespace::clean ;

use lib '/home/dave/code/repeat-until/lib' ;
use Repeat::Until ;

use feature qw(signatures) ;

no warnings qw(experimental::signatures) ;

# ===== NOTES ==================================================================

# Tor flags your circuit as being 'dirty' after ten minutes and makes further
# connections on a new one. You can change this by setting the 'MaxCircuitDirtiness'
# torrc option.
# - 10 minutes is plenty, I don't adjust this

# To get the exit node IP, this is interesting:
#    https://stackoverflow.com/questions/32448750/how-to-get-the-tor-exitnode-ip-with-python-and-stem
#    BUT it works by watching while a request is made. So not much gain over asking
#    an external site for the IP.

# This seems closer: https://stackoverflow.com/questions/9777192/how-do-i-get-the-tor-exit-node-ip-address-over-the-control-port

# ===== FILE GLOBALS ===========================================================

# ===== ATTRIBUTES =============================================================
has _the_socket => ( is => 'rw', isa => Maybe [ InstanceOf ['IO::Socket::INET'] ], required => 0, default => undef ) ;

has debug               => ( is => 'ro',   isa => Int,  required => 1, default => 0 ) ;
has timeout             => ( is => 'ro',   isa => Int,  required => 1, default => 20 ) ;
has quiet               => ( is => 'ro',   isa => Bool, required => 1, default => 1 ) ;
has check_unique_ip     => ( is => 'ro',   isa => Bool, required => 1, default => 0 ) ;
has circuit_established => ( is => 'rw',   isa => Bool, required => 0, default => 0 ) ;
has protocol            => ( is => 'ro',   isa => Str,  required => 1, default => 'socks' ) ;
has control_password    => ( is => 'ro',   isa => Str,  required => 1, default => 'pAsSwOrD' ) ;
has _hashed_password    => ( is => 'lazy', isa => Str ) ;
has _proc               => ( is => 'lazy', isa => InstanceOf ['Proc::Background'], predicate => 1 ) ;
has _data_dir           => ( is => 'lazy', isa => InstanceOf ['Path::Tiny'] ) ;
has _control_port       => ( is => 'lazy', isa => Int ) ;
has port                => ( is => 'lazy', isa => Int ) ;
has proxy_str           => ( is => 'lazy', isa => Str ) ;
has _initialised        => ( is => 'rw',   isa => Bool,    default => 0, required => 0 ) ;
class_has _seen_ip      => ( is => 'ro',   isa => HashRef, default => sub { {} } ) ;

# ===== CONSTRUCTORS ===========================================================
around BUILDARGS => sub {
    my ( $orig, $class, %args ) = @_ ;
    return \%args ;
    } ;


sub BUILD ( $self, $args ) {
    $self->_proc ;
    $self->_initialised(1) ;
    $self->_check_unique_ip if $self->check_unique_ip ;
    }


sub DEMOLISH {
    my ( $self, $in_global_destruction ) = @_ ;

    if ( $self->_has_proc ) {
        repeat_until { $self->_send_rcv_says( 'SIGNAL SHUTDOWN' => '250 OK' ) } 5 ;
        }

    if ( $self->_initialised ) {
        my $pb = $self->_proc ;
        $pb->terminate ;
        my $sysexit = $pb->wait ;

        my $pid = $pb->pid ;
        $self->_debug( 1, "Proc::Background [$pid] sig: " . $pb->exit_signal ) ;
        $self->_debug( 1, "Proc::Background [$pid] xit: " . $pb->exit_code ) ;
        $self->_debug( 1, "Proc::Background [$pid] sys: $sysexit" ) ;
        }

    $self->_data_dir->remove_tree ;

    return ;    # don't accidentally return the deleted socket
    }


sub _build__data_dir ($self) {
    Path::Tiny->tempdir ;
    }


sub _build__control_port ($self) {
    empty_port() ;
    }


sub _build_port ($self) {
    my $control_port = $self->_control_port ;
    repeat_until { my $port = empty_port() ; return $port == $control_port ? undef : $port } ;
    }


sub _build__hashed_password ($self) {
    my $pwd             = $self->control_password ;
    my $hashed_password = qx(tor --hash-password $pwd) ;

    ($hashed_password) = $hashed_password =~ /(16:\w*)$/s ;

    die "Command 'tor --hash-password $pwd' did not produce a tor password" unless $hashed_password ;

    return $hashed_password ;
    }


sub _build__proc ($self) {
    my $tor = which('tor') || croak 'could not find tor binary in $PATH' ;

    my @tor_cmd = (
        $tor,
        "--ControlPort"           => $self->_control_port,
        "--SocksPort"             => $self->port,
        "--DataDirectory"         => $self->_data_dir,
        "--HashedControlPassword" => $self->_hashed_password,
        ) ;

    push( @tor_cmd, '--quiet' ) if $self->quiet ;

    my $tor_proc = Proc::Background->new(@tor_cmd) ;

    croak "Error running tor. Run with quiet => 0 to get a hint." unless $tor_proc->alive ;

    my $pid = $tor_proc->pid ;
    $self->_debug( 1, "Proc::Background [$pid] cmd: " . join( ' ', @tor_cmd ) ) ;

    $self->circuit_established(1) if repeat_until {
        $self->_send_rcv_says( "GETINFO status/circuit-established" => 'circuit-established=1' )
        }
    $self->timeout ;

    if ( !$self->circuit_established ) {
        $tor_proc->terminate ;
        $tor_proc->wait ;
        die "Couldn't confirm established circuit - try with quiet => 0 and/or debug => 2 to debug" ;
        }

    $self->_debug( 1, 'Circuit established OK' ) ;

    return $tor_proc ;
    }


sub _build_proxy_str ($self) {
    $self->protocol . "://localhost:" . $self->port ;
    }

# ===== CLASS METHODS ==========================================================


sub _seen ( $proto, $ip ) {
    return 1 if $proto->_seen_ip->{$ip}++ ;
    return 0 ;
    }

# ===== INSTANCE METHODS =======================================================


sub _socket ($self) {
    return $self->_the_socket if $self->_the_socket ;

    my $s = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $self->_control_port,
        ) ;

    $self->_the_socket($s) ;

    return $s if $s ;

    die "Could not connect to tor through control port " . $self->_control_port ;
    }


sub _send_rcv_says ( $self, $msg, $wanted ) {
    my $response = $self->_send_rcv($msg) || '' ;
    return 1 if $response eq $wanted ;

    $self->_debug( 2, "Unexpected response to [$msg]: $response (expected: $wanted)" ) ;
    return 0 ;
    }


sub _send_rcv_ok ( $self, $msg ) {
    $self->_send_rcv($msg) ? 1 : 0 ;
    }


sub _send_rcv ( $self, $msg ) {

    try {
        return unless $self->_authenticate ;

        my $answer = $self->_send($msg) ;

        return unless $answer ;

        return '250 OK' if $msg =~ /^SIGNAL / ;    # signals only reply success or failure - and we already know it's not failure

        my ( $response_line, $status ) = split /\r\n/, $answer ;

        $response_line =~ /^250-(?:status|ip-to-country)\/(.*)$/ ;
        my $response = $1 ;

        $self->_debug( 3, 'Status',        $status ) ;
        $self->_debug( 3, 'Response line', $response_line ) ;
        $self->_debug( 2, 'Response',      $response ) ;

        die "Unrecognised response in answer: $answer" unless $response ;
        die "Error $status for msg [$msg]: $response"  unless $status eq '250 OK' ;

        return $response ;
        }

    catch ($e) {
        $self->_debug( 2, 'Caught error', $e ) ;
        return ;
        }
    }


sub _send ( $self, $msg ) {
    my $socket = $self->_socket ;
    my $answer = '' ;

    $socket->send("$msg\r\n") ;
    $socket->recv( $answer, 1024 ) ;

    # $socket->send("QUIT\r\n") ;

    $self->_debug( 3, 'MESSAGE', $msg ) ;
    $self->_debug( 3, 'Answer',  $answer ) ;

    return $answer if $answer =~ /250 OK/ ;
    return $answer if $answer =~ /250\+/ ;    # multiline responses
    return ;
    }


sub _authenticate ($self) {
    my $socket   = $self->_socket ;
    my $password = $self->control_password ;
    my $answer   = '' ;

    $socket->send(qq(AUTHENTICATE "$password"\r\n)) ;
    $socket->recv( $answer, 1024 ) ;

    if ( $answer =~ /250 OK/ ) {
        $self->_debug( 2, 'Authenticated OK' ) ;
        return 1 ;
        }

    $self->_debug( 2, 'FAILED authentication' ) ;
    return 0 ;
    }

# ! Ugly hack, all in all better just to create a new Tor::Proxy object every time
# ! you want a new endpoint IP.
# after sending SIGNAL NEWNYM, might want to run this with $reps = 10, as a hack to get the
# thing to actually change the endpoint (sometimes takes a few tries to make the switch 'stick')
sub rotate_ip ( $self, $ensure = 1, $ip = undef ) {
    return $self->_send_rcv_ok('SIGNAL NEWNYM') unless $ensure ;

    $ip ||= $self->get_endpoint_ip ;
    return 0 unless $self->_send_rcv_ok('SIGNAL NEWNYM') ;
    return repeat_until { $self->get_endpoint_ip(10) ne $ip } 10 ;
    }

# https://askubuntu.com/questions/941967/how-to-print-tor-external-ip-in-terminal
sub get_endpoint_ip ($self) {
    my $proxy_str = $self->proxy_str ;

    # return qx(curl --silent --proxy $proxy_str --header "Connection: close" https://ipinfo.io/ip) ;

    my $html = qx(curl --silent --proxy $proxy_str --header "Connection: close" https://check.torproject.org) ;

    die "Couldn't find IP" unless $html =~ /<strong>([\d\.]+)<\/strong/ ;
    return $1 ;
    }


sub _get_country ( $self, $ip ) {
    my $cc = $self->_send_rcv("GETINFO ip-to-country/$ip") ;

    $cc =~ s/^$ip=// ;

    $self->_debug( 1, "IP $ip", "CC: $cc" ) ;

    return $cc ;
    }


sub get_endpoint_cc ($self) {
    my $ip = $self->get_endpoint_ip ;
    my $cc = $self->_get_country($ip) ;
    return wantarray ? ( $cc, $ip ) : $cc ;
    }

# This should only be called a maximum of once per proxy. Only checks uniqueness
# of endpoints created in the current process, so YMMV.
sub _check_unique_ip ($self) {
    my $ip = $self->get_endpoint_ip ;

    croak("No IP")             if !$ip ;
    croak("IP did not rotate") if $self->_seen($ip) ;

    $self->_debug( 1, sprintf "Tor proxy at %s is connected to endpoint $ip", $self->proxy_str ) ;
    }


sub _debug ( $self, $level, $topic, $msg = '' ) {
    return unless $self->debug >= $level ;
    $topic .= ':' if $msg ;
    print STDERR sprintf "[$$ %s] %-15s $msg\n", __PACKAGE__, $topic ;
    }

1 ;

# ===== DOCS ===================================================================

=pod

=head1 NAME

C<Tor::Proxy> - launch Tor and get a proxy string to use in other apps on localhost

=head1 SYNOPSIS

    use Tor::Proxy ;

    my $tp = Tor::Proxy->new(
        protocol            => 'socks5',        # socks socks5h http... (default: socks)
        quiet               => 1,               # tell tor to be quiet (default: 1)
        debug               => 3,               # increasing levels of verbosity (default: 0)
        check_unique_ip     => 1,               # ensure the endpoint IP is unique (default: 0)
        control_password    => 'pAsSwOrD',      # (default: pAsSwOrD)
        ) ;

    my $ip = $tp->get_endpoint_ip ;
    my $cc = $tp->get_endpoint_cc ;

    my $port = $tp->port ;

    my $proxy_str = $tp->proxy_str ;     # socks5://localhost:$port

    # get the news via $ip in $cc
    my $news = qx(curl --silent --proxy $proxy_str https://www.bbc.com/) ;


=head1 DESCRIPTION

Launch Tor and get a proxy string to use in other apps on localhost.

You can safely launch as many of these things at the same time as you want, either
from the same parent process, or after forking.

When the object goes out of scope, the tor process is shut down cleanly.

Each tor instance has a different endpoint. If you want to guarantee unique endpoints,
set 'check_unique_ip'. This will check that all tor processes launched *from the current
parent process* are unique. So it doesn't make sense to set this flag if you
fork before launching each tor. But endpoints seem to be pretty reliably unique in any case.

=cut
