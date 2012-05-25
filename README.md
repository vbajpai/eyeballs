Happy Eyeballs
--------------
- - -

Concurrent DNS lookups for `A` and `AAAA` records for one or more hosts.


Usage
-----
- - -

	>> bin/dns [-s namesever] host[s]


Build and Run
-------------
- - -

	>> make
	>> bin/dns facebook.com google.com ietf.org
	using nameserver: 8.8.8.8
	
	facebook.com
	66.220.149.11
	66.220.158.11
	69.171.229.11
	69.171.242.11
	2a03:2880:10:1f02:face:b00c::25
	2a03:2880:10:8f01:face:b00c::25
	2a03:2880:2110:3f01:face:b00c::
	
	google.com
	173.194.69.138
	173.194.69.101
	173.194.69.100
	173.194.69.102
	173.194.69.113
	173.194.69.139
	
	ietf.org
	12.22.58.30
	2001:1890:123a::1:1e