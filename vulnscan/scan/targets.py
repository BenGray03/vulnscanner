from typing import List, Tuple, Union
import ipaddress
_PORT_MIN, _PORT_MAX = 1, 65535
PortRange = Tuple[int, int] 

def convert_ports(input_ports: str)-> List[PortRange]:
    if input_ports is None:
        raise ValueError("Port spec cannot be None")
    s = input_ports.strip()


    if s in {"-", "-p-"}:
        return [(_PORT_MIN, _PORT_MAX)]

    raw: List[PortRange] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                start, end = int(a), int(b)
            except ValueError:
                raise ValueError(f"Invalid range: '{part}'")
            if start > end:
                start, end = end, start  
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port: '{part}'")
            start = end = p

        if start < _PORT_MIN or end > _PORT_MAX:
            raise ValueError(f"Port(s) out of range in '{part}'; valid {_PORT_MIN}-{_PORT_MAX}")

        raw.append((start, end))

    if not raw:
        raise ValueError("Empty port spec")

    raw.sort()
    merged: List[PortRange] = []
    cs, ce = raw[0]
    for s2, e2 in raw[1:]:
        if s2 <= ce + 1:
            ce = max(ce, e2)
        else:
            merged.append((cs, ce))
            cs, ce = s2, e2
    merged.append((cs, ce))
    return merged

def is_ip(input: str):
    try:
        ipaddress.ip_address(input)
        return True
    except ValueError:
        return False
    

def expand_cidr(network: str) -> list[str]:
    network = ipaddress.ip_network(network, strict=False)

    return[str(ip) for ip in network.hosts()]