# Ubuntu Guard
Watcher which detects malicious requests or attempts.  

Watches: 
* The `/var/log/auth.log` file (if exists)
* The `/var/log/apache2` directory (if exists)
* The `/var/log/nginx` directory (if exists)
 
Creates an IP table using `iptables` or `ip6tables` and manages IP addresses
