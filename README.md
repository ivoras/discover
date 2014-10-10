Discover
========

Discover is a p2p program and library that lets you register
and discover sibling servers in the network based on a shared
passphrase. It uses the Mainline DHT network to advertise its own
existence and to look for other nodes that are running with the same
passphrase.

It authenticates sibling peers using an HMAC-based mechanism.

This code is based on Wherez (https://github.com/nictuku/wherez)

Possible usages
---------------

- find the location of your company's doozerd, Chubby or DNS servers.
- robust way for stolen notebooks to "phone home".
- register and locate servers in a corporate network based on
function, by using different passphrases for the DNS server, LDAP
server, etc.


Example application
-------------------

Example CLI usage:

    $ make && ./discover 8080 "wherezexample"
    peer found: 14.15.87.13:3111
    peer found: 77.66.77.22:3211
    peer found: 16.97.12.12:3312

8080 is your application's port to be advertised to other nodes.

The IP:port pairs that appear are those peers provided by nodes that have been contacted and authenticated.

Recently started nodes may take several minutes to find other peers and to be found by them.

How does it work?
------------------

Presentation: http://goo.gl/vn7Pvh
