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
    my $news = qx(curl --silent --proxy $proxy_str --header "Connection: close" https://www.bbc.com/) ;

# DESCRIPTION

Launch Tor and get a proxy string to use in other apps on localhost
