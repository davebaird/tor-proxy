# NAME

`Tor::Proxy` - launch Tor and get a proxy string to use in other apps on localhost

# SYNOPSIS

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

# DESCRIPTION

Launch Tor and get a proxy string to use in other apps on localhost.

You can safely launch as many of these things at the same time as you want, either
from the same parent process, or after forking.

When the object goes out of scope, the tor process is shut down cleanly.

Each tor instance has a different endpoint. If you want to guarantee unique endpoints,
set 'check\_unique\_ip'. This will check that all tor processes launched \*from the current
parent process\* are unique. So it doesn't make sense to set this flag if you
fork before launching each tor. But endpoints seem to be pretty reliably unique in any case.
