# VIP PING (Virtual IP Ping)

```
Usage: vipping [OPTIONS] --interface <INTERFACE> --source <SOURCE> --destination <DESTINATION>

Options:
  -i, --interface <INTERFACE>      Local interface
  -s, --source <SOURCE>            Source IP
  -d, --destination <DESTINATION>  Destination IP
  -g, --gateway <GATEWAY>          Gateway IP
  -t, --timeout <TIMEOUT>          Timeout in seconds [default: 1]
  -h, --help                       Print help
```

### Usage:
```bash
sudo vipping -i ens8 -s 10.0.0.123 -d 10.0.0.1 -t 1
```

The successful output would look like:
```
0.807 ms
```

The error output would look like:
```
Error: Could not find MAC address for 10.0.0.1
```