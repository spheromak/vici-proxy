## StrongSwan VICI proxy

A small proxy to allow finer control over the VICI socket.

The intent is to restrict what commands can be sent to VICI in order to allow unprivileged access to some commands.


## Usage
Simple usage should be to invoke with an allow-list that enables stats

```
vici-proxy -a stats

```

### Arguments


```
--allow -a  The allow list can be specified multiple times. Keywords match vici commands (default ``)
--deny -d The deny list can be specified multiple times. Keywords match vici commands, special keyword `all` denys all. Allow rules apply first. (default `all`)
--listen -l The socket file to listen on. (defaults: /var/run/proxy.vici)

```

TODO:
* AllowList of commands
* authentication
* DenyList of commands
