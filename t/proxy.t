#!/usr/bin/env perl
use v5.28 ;
use warnings ;
use Carp ;
use Data::Dumper ;

use Parallel::ForkManager ;

use lib '/home/dave/code/tor-proxy/lib' ;
use Tor::Proxy ;

use feature qw(signatures) ;

no warnings qw(experimental::signatures) ;

$SIG{INT} = sub { croak "Caught INT"  } ;

my %proxies ;

my $run_on_finish = sub {
    my ( $pid, $exit, $id, $signal, $coredump, $data ) = @_ ;

    $proxies{$id} = {
        id        => $data->[0],
        proxy_str => $data->[1],
        ip        => $data->[2],
        cc        => $data->[3],
        } ;
        } ;

my $pm = Parallel::ForkManager->new( max_proc => 3 ) ;

$pm->run_on_finish($run_on_finish) ;

foreach my $id (1) {
    $pm->start($id) and next ;

    my $tp = make_tp($id) ;

    $pm->finish( 1, [ $id ] ) unless $tp->circuit_established ;

    my $proxy_str = $tp->proxy_str ;
    my $ip        = $tp->get_endpoint_ip ;
    my $cc        = $tp->get_endpoint_cc ;

    warn "Child $id: proxy and IP: $proxy_str -> $ip in geo: $cc\n" ;

    # analyse_circs($tp) ;

    $pm->finish( 0, [ $id, $proxy_str, $ip, $cc ] ) ;
    }

warn "Parent: waiting all children\n" ;

$pm->wait_all_children ;

printf "Got %s tors\n", scalar( keys %proxies ) ;

print Dumper ( \%proxies ) ;


sub make_tp ( $username, $check_ip = 0 ) {
    Tor::Proxy->new(
        protocol        => 'socks5',
        quiet           => 1,
        debug           => 0,
        check_unique_ip => $check_ip,
        ) ;
    }


sub analyse_circs ($tp) {
    my $circs = $tp->_send('GETINFO circuit-status') ;
    my @circs = split /\r\n/, $circs ;
    print "Z5: $_\n" for @circs ;

    my $cdata ;

    foreach my $circ (@circs) {
        next if $circ =~ /^250\+/ ;

        say '' ;
        say "Analysing: $circ" ;

        if ( $circ =~ /^(\d+) BUILT ([^\s]+)(?: (.+))?$/ ) {
            my ( $id, $fpnicks, $rest ) = ( $1, $2, $3 ) ;
            $rest ||= '' ;

            my @fp ;
            foreach my $fpnick ( split /,/, $fpnicks ) {
                if ( $fpnick =~ /^\$(\w+)\~(\w+)$/ ) {
                    push @fp,
                        {
                        fingerprint => $1,
                        nick        => $2,
                        } ;
                    }
                }

            my @rest = split /\s/, $rest ;

            my ( %kv, @flags ) ;
            foreach my $item (@rest) {
                my ( $k, $v ) = split /=/, $item ;
                if ( $v =~ /,/ ) {
                    my @v = split /,/, $v ;
                    $kv{$k} = \@v ;
                    }
                else {
                    $kv{$k} = $v ;
                    }
                }

            $cdata->{$id} = {
                id       => $id,
                fp_nicks => \@fp,
                raw      => $circ,
                rest     => $rest,
                %kv,
                } ;
            }
        else {
            say "*** DID NOT MATCH ***" ;
            }
        }

    print Dumper($cdata) ;

    get_nodeinfo( $tp, $cdata ) ;

    }


sub get_nodeinfo ( $tp, $cdata ) {

    # ns/id/<OR identity>
    foreach my $circ_id ( sort keys $cdata->%* ) {
        my $circ_data = $cdata->{$circ_id} ;

        foreach my $fp_nick ( $circ_data->{fp_nicks}->@* ) {
            my $fp = $fp_nick->{fingerprint} ;

            my $report = $tp->_send("GETINFO ns/id/$fp") ;
            say '' ;
            say "Report for fp $circ_id: $fp" ;
            say $report if $report ;
            }
        }

    }
