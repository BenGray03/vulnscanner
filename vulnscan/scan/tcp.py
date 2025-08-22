import asyncio
from datetime import datetime
from typing import List, Tuple, Iterable

_PORT_MIN, _PORT_MAX = 1, 65535
PortRange = Tuple[int, int] 

COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2379: "etcd",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

BANNER_HINTS: list[tuple[str, str]] = [
    ("SSH-", "ssh"),
    ("OpenSSH", "ssh"),
    ("220", "smtp"),                # Many SMTP banners start with 220
    ("ESMTP", "smtp"),
    ("IMAP", "imap"),
    ("POP3", "pop3"),
    ("MySQL", "mysql"),
    ("PostgreSQL", "postgres"),
    ("Redis", "redis"),
    ("mongodb", "mongodb"),
    ("HTTP/", "http"),              # if a server ever sends a banner (rare without a request)
    ("nginx", "http"),
    ("Apache", "http"),
    ("Microsoft-IIS", "http"),
    ("RFB", "vnc"),                 # VNC "RFB 003.008"
    ("SMB", "smb"),
    ("FTP", "ftp"),
    ("Telnet", "telnet"),
    ("LDAP", "ldap"),
]

async def tcp_banner_grab(target: str, port: int, timeout : float = 2.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout)
    except Exception:
        return None
    
    banner = None
    try:
        banner = await asyncio.wait_for(reader.read(128), timeout=0.5)
        if banner:
            banner = banner.decode(errors="ignore").strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    
    svc = service_guess(port, banner)
    return {"host": target, "port": port, "banner": banner, **svc}

async def scan_ports(target: str, ports: List[PortRange], timeout:float = 2.5, sem: int = 500):

    open_ports = []
    semaphore = asyncio.Semaphore(sem)

    async def check_port(port:int):
        async with semaphore:
            try:
                conn = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                print("[+] Port found open:", port)
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
                
            except Exception:
                pass
    print("Scanning started at", datetime.now())
    tasks = [check_port(port) for port in iterate_ports(ports)]
    await asyncio.gather(*tasks)

    return {"host": target, "open_ports": open_ports}

def service_guess(port: int, banner: str | None):
    service = None
    confidence = "low"
    protocol = "tcp"
    tls = False

    if banner:
        lower_banner = banner.strip().lower()

        for needle, svc in BANNER_HINTS:
            if needle.lower() in lower_banner:
                service = svc
                confidence = "medium"
                break
        
    if service is None and port in COMMON_PORTS:
        service = COMMON_PORTS[port]
        confidence = "low"

    if service in {"https", "imaps", "pop3s", "smtps"} or port in {443, 465, 993, 995, 8443}:
        tls = True

    return {
        "service": service,
        "protocol": protocol,   
        "tls": tls,   
        "confidence": confidence,
    }

async def grab_banners_for_ports(target: str, ports: List[PortRange], timeout: int = 2.5, sem: int = 200):
    semaphore = asyncio.Semaphore(sem)

    async def grab(port:int):
        async with semaphore:
            return await tcp_banner_grab(target, port, timeout)
    
    tasks = [grab(port) for port in iterate_ports(ports)]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]

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

def iterate_ports(ranges: List[PortRange])-> Iterable[int]:
    for start, end in ranges:
        for p in range(start, end +1):
            yield p

async def scan_host_tcp(target: str, ports: str,
                        timeout: float = 2.5, sem: int = 500) -> dict:
    converted_ports = convert_ports(ports)
    print(converted_ports)
    scan = await scan_ports(target, converted_ports, timeout=timeout, sem=sem)
    ports = scan["open_ports"]
    results = await grab_banners_for_ports(target, converted_ports, timeout=timeout, sem=min(sem, 200))
    return {"host": target, "open_ports": ports, "results": results}
 