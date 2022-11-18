# Watchsock

Watchsock is a simple command line utility that monitors tcp sockets for changes, it can currently detect:
* new created sockets
* terminated sockets
* transitions of socket state

Watchsock detects changes in tcp sockets by scanning every 500ms through netlink sock_diag requests.


### How to use


Launch:
```bash
$ watchsock

observing host sockets for changes ..
..
inode: 218552   uid: 1000       src: 10.0.2.15:56456      dst: 72.21.91.29:80       reason: added  
inode: 213556   uid: 1000       src: 10.0.2.15:39370      dst: 23.221.223.26:80     reason: TCP_SYN_SENT->TCP_ESTABLISHED
inode: 213555   uid: 1000       src: 10.0.2.15:39356      dst: 23.221.223.26:80     reason: TCP_SYN_SENT->TCP_ESTABLISHED
inode: 218553   uid: 1000       src: 10.0.2.15:56466      dst: 72.21.91.29:80       reason: added  
..
```
