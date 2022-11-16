# Watchsock

Watchsock is a simple command line utility that monitors tcp sockets for changes, it can currently detect:
* new created sockets
* terminated sockets
* transitions of socket state


### How to use

```bash
$ watchsock

observing host sockets for changes ..
id: 0, reason: state change TCP_LISTEN -> TCP_FIN_WAIT2, uid: 0, inode 0, src: 127.0.0.1:9080, dst: 127.0.0.1:59280
id: 0, reason: state change TCP_FIN_WAIT2 -> TCP_TIME_WAIT, uid: 0, inode 0, src: 127.0.0.1:9080, dst: 127.0.0.1:59280
..
```
