example.com.	3600	IN	SOA	ns1.example.com. postmaster.example.com. 2009060309 10800 3600 604800 3600
example.com.	86400	IN	NS	ns1.example.com.
example.com.	86400	IN	NS	ns2.example.com.
ns1.example.com.	86400	IN	A	192.0.2.1
ns2.example.com.	86400	IN	A	192.0.2.2
