# mmbop

Dynamic DNS ([RFC 2136](https://tools.ietf.org/html/rfc2136)) provides a mechanism for updating entries in a zone file without needing to edit that file by hand and without needing to restart BIND. For Python users, the [dnspython](http://www.dnspython.org/) module provides a valuable foundation for creating dynamic DNS applications. However there are some things that dnspython and dynamic DNS cannot do - specifically, the creation of new authoritative zones.

BIND does come with a program, rndc, that can control various aspects of the name service, locally or remotely. One of the functions is adding a zone. However the command relies on the fact that the empty zone file already exists. So there is a need for a program to wrap rndc functionality and provide push button capability to add/remove zones. This is the purpose of mmbop.

## Getting Started

Clone the repository and you should be almost done. A (successful) attempt was made to only use modules from the standard library, so there are no Python dependencies when using the command-line (mmbop.py). For the API (mmbop_api.py), [Falcon](https://falconframework.org/) is used and required.

### Prerequisites

A working DNS environment would be useful. In *named.conf* (or associated configuration files), you will need a *controls* stanza that specifies the key that rndc is allowed to use, along with the acl defining the source (in our case, mmbop is run locally, so 127.0.0.1 - aka, localhost - is sufficient).

```
include "/etc/bind/rndc.key";

controls {
        inet * allow { localhost; } keys { "rndc-key"; };
};
```

If you are running BIND version 9.11.0 or later and wish to take advantage of the catalog zone feature (allowing you to automatically update secondary nameservers with the new zones you have created), the appropriate configuration is required on both the primary and secondary server(s).

Primary (for example sake, this has IP 10.1.1.1):
```
        catalog-zones {
                zone "catalog.zone";
        };

zone "catalog.zone" {
        type master;
        file "catalog.zone.db";
        allow-update { key rndc-key; };
};
```

Secondary:
```
        catalog-zones {
                zone "catalog.zone" default-masters { 10.1.1.1; };
        };

zone "catalog.zone" {
        type slave;
        file "/etc/bind/catalog.zone.db";
        masters { 10.1.1.1; };
};
```

See [this nice introduction](https://kb.isc.org/docs/aa-01401) to catalog zones for more information.

**Python and BIND version requirements**

The code was developed using Python 3.6.8 and BIND 9.14.3.
The code was successfully deployed using Python 3.7.4 and BIND 9.11.2rc2

Python 3.6+ is required as mmbop relies on a change in *subprocess* that accepts an *encoding* parameter. This matters for the catalog zone update.
BIND 9.11+ is required to support catalog zones.

### Installing

Assuming now you have at least a working primary DNS server that is accepting a local rndc connection, and you cloned this repository.

**Step 1 : Configure mmbop.ini**

Rename the example file to *mmbop.ini* and edit it so that the required values match your environment.

```
[RNDC]
server: 127.0.0.1
port: 953
keyfile: /etc/bind/rndc.key
path: /usr/sbin/rndc

[DNS]
dns1: ns1.example.com
dns2: ns2.example.com
serial: 1
owner: hostmaster.example.com
namedir: /etc/bind
nameown: bind
namegrp: bind
nameper: 0644

[MMBOP]
protect: example.com|example.net
require: .example.com|.example.net
options: also-notify { 10.10.10.1; };|allow-update { key "myddnskey"; };
catalog: catalog.example
Give the example
```
The .ini file comments explain each option, but the 2 least obvious ones (as they are specific to the mmbop application) are *protect* and *require*.

- protect: A list (entries separated by '|') of exact domain names that mmbop is not allowed to manage (add/remove). Typically used to protect the parent zone, if you are looking to make subdomains only.
- require: A list (entries separated by '|') of end of string matches. For mmbop to manage a domain, it must match at least one of these strings. Typically used to specify the subdomain (note preceeding '.' in example above).

**Step 2 : Verify by running mmbop for server status**

```
# python mmbop.py status
version: BIND 9.14.5-Ubuntu (Stable Release) <id:c2c2b6d>
running on example_server: Linux x86_64 4.15.0-62-generic #69-Ubuntu SMP Wed Sep 4 20:55:53 UTC 2019
boot time: Fri, 22 Nov 2019 21:43:09 GMT
last configured: Tue, 14 Jan 2020 19:09:32 GMT
configuration file: /etc/bind/named.conf
CPUs found: 2
worker threads: 2
UDP listeners per interface: 2
number of zones: 14 (0 automatic)
debug level: 0
xfers running: 0
xfers deferred: 0
soa queries in progress: 0
query logging is OFF
recursive clients: 0/900/1000
tcp clients: 4/150
server is up and running
```
If you see output similar to the example above, congrats you have a working mmbop setup.
If this doesn't work, run with verbose logging (*-v*) for more details on the problem.

**Step 3 : Add a zone**

Given what mmbop is required to do to add a domain, it is necessary to run as a user with write permissions to the directory where the zone files are located.

You can run it as root (sudo), or - from root - you can sudo and run as the same user that owns the BIND service and files. By default, on Ubuntu this is the *bind* user, which is created when you install BIND.

```
# python mmbop.py zoneadd nina.example.com
Add of zone nina.example.com succeeded

# python mmbop.py zonestatus nina.example.com
name: nina.example.com
type: master
files: nina.example.com.db
serial: 1
nodes: 1
last loaded: Tue, 14 Jan 2020 19:07:45 GMT
secure: no
dynamic: yes
frozen: no
reconfigurable via modzone: yes
```

**Step 4 : Remove a zone**

```
# python mmbop.py zonedel nina.example.com
Deletion of zone nina.example.com succeeded

# python mmbop.py zonestatus nina.example.com
rndc: 'zonestatus' failed: not found
no matching zone 'nina.example.com' in any view
```

**Step 5 : Explore**

Run with *-h* or *--help* to see all of the available command-line options

```
$ python mmbop.py --help
usage: mmbop.py [-h] [-v] [-c FILE]
                {status,query,hostadd,alias,hostdel,hostlist,hostsearch,zoneadd,zonedel,zonelist,zonestatus}
                ...

mmbop manages BIND over Python

optional arguments:
  -h, --help                      show this help message and exit
  -v, --verbose                   Enable verbose messages
  -c FILE, --config FILE          Location of config file

commands:
  DNS actions

  {status,query,hostadd,alias,hostdel,hostlist,hostsearch,zoneadd,zonedel,zonelist,zonestatus}
                                  add -h after command for additional
                                  information
    status                        Return status of BIND
    query                         Query for name or IP
    hostadd                       Add an A and PTR record
    alias                         Add a CNAME record
    hostdel                       Remove CNAME or A and PTR record
    hostlist                      Show all records for zone
    hostsearch                    Wildcard search of a zone
    zoneadd                       Add a zone
    zonedel                       Remove a zone
    zonelist                      Show all zones
    zonestatus                    Show status of a zone
```

Note that the *zonelist* option will only show the domains that mmbop can manage (using same validation criteria as for adding/removing zones) - see above for the protect/require configuration. Also note that list works by running 'rndc dumpdb -zones' and then parses this file to obtain the applicable domains. It has to wait for the dump file to complete writing, which can take a surprisingly long (relatively speaking) time - 6+ seconds if you have a lot of large zone files.

## API

It may be desirable to provide the ability to add/remove zones, without wanting to give these users shell access to the primary DNS server. The script *mmbop.py* provides a simple REST API interface, which can be used with your favorite [WSGI](https://www.python.org/dev/peps/pep-3333/) capable web server to provide remote access to the application. There is a simple header-based authorization token solution for validating requests; for production use you will likely want something more robust (and/or handled directly through the web server controls).

**Step 1 : Configure mmbop_api.ini**

The only item in this configuration file is the SHA224 hashed hexidecimal digest of the token string that the client will provide in the web request.

To generate the hash, you can run python directly:

```
$ python3 -q
>>> import hashlib
>>> clear_token = 'mysupersecretkey'
>>> hash_token = hashlib.sha224(clear_token.encode()).hexdigest()
>>> print(hash_token)
fb096d8fa48b12cf2adec03e5e5d03fb231bb87674f8d8dbf137f05c
```
Added to the *mmbop_api.ini* file:

```
[DEFAULT]
token:fb096d8fa48b12cf2adec03e5e5d03fb231bb87674f8d8dbf137f05c
```
Given this, for a request to be valid the client must send *mysupersecretkey* as the value in the *Authorization* field of the header. See the examples below.

**Step 2 : Start service**

For the purpose of providing an example, gunicorn will be directly used. By default this starts the service listening locally on port 8000.

See [this guide](https://www.digitalocean.com/community/tutorials/how-to-deploy-falcon-web-applications-with-gunicorn-and-nginx-on-ubuntu-16-04) for using gunicorn with nginx.

For production, you should use https to keep the auth token secure.

```
$ sudo gunicorn mmbop_api:APP
[2019-08-22 15:35:53 -0400] [16586] [INFO] Starting gunicorn 19.9.0
[2019-08-22 15:35:53 -0400] [16586] [INFO] Listening at: http://127.0.0.1:8000 (16586)
[2019-08-22 15:35:53 -0400] [16586] [INFO] Using worker: sync
[2019-08-22 15:35:53 -0400] [16589] [INFO] Booting worker with pid: 16589
```

Example 1: Listing all zones:

```
$ curl -i -H "Content-Type: application/json" -H "Authorization: mysupersecretkey" http://127.0.0.1:8000/zonelist
HTTP/1.1 200 OK
Server: gunicorn/19.9.0
Date: Thu, 22 Aug 2019 19:42:08 GMT
Connection: close
content-length: 41
content-type: application/json
scott.example.com sarah.example.net
```
The use of *-i* in curl is just to show the response code, not required for obtaining a result

Example 2: Adding an invalid zone (does not meet the protect/require standards):

```
$ curl -i -X POST -H "Content-Type: application/json" -H "Authorization: mysupersecretkey" -d '{"domain":"bogus.company.com"}' http://127.0.0.1:8000/modify
HTTP/1.1 400 Bad Request
Server: gunicorn/19.9.0
Date: Thu, 22 Aug 2019 20:14:45 GMT
Connection: close
content-length: 43
content-type: application/json

Not a valid zone name. Check configuration.
```

**Current list of API functions and their allowed methods:**

- /query
    - equivalent to: mmbop query <entry>
    - GET
    - Required params: entry
- /status
    - equivalent to: mmbop status
    - GET
- /hostmodify
    - equivalent to: mmbop hostadd <fqdn> <add> or mmbop hostdel <fqdn|addr>
    - POST (adding entries), DELETE (removing entries)
    - Required params: fqdn, addr (if POST)
    - Optional params: force
- /alias
    - equivalent to: mmbop alias <alias> <real>
    - POST (adding entries; for removing, use /hostmodify)
    - Required params: alias, real
    - Optional params: force
- /hostlist/{domain}
    - equivalent to: mmbop <domain>
    - GET
- /hostsearch
    - equivalent to: mmbop <domain> <term>
    - GET
    - Required params: domain
    - Optional params: term
- /zonemodify
    - equivalent to: mmbop zoneadd <domain> or mmbop zonedel <domain>
    - POST (adding zones), DELETE (removing zones)
    - Required params: domain
- /zonelist
    - equivalent to: mmbop zonelist
    - GET
- /zoneinfo/{domain}
    - equivalent to: mmbop zonestatus <domain>
    - GET

## Built With

* [VIM](https://www.vim.org/) - venerable and more than capable
* [Pylint](https://www.pylint.org/) - keeping my code somewhat under control and consistent

## Authors

* **Scott Strattner** - [IBM Github](https://github.ibm.com/sstrattn)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Thanks to [dnspython](http://www.dnspython.org/) I was able to reverse engineer the weird 'wire format' required for catalog zone entries
* [This](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2) nice README template
