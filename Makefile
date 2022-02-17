

readme:
	perl -MPod::Markdown -e 'Pod::Markdown->new->filter(@ARGV)' lib/Tor/Proxy.pm > README.md
