import asyncio
from ping3 import ping
from .targets import expand_cidr

def icmp_ping_single(host_ip: str, timeout: int):
    """
    Simple ICMP ping that pings a single host and tells us if it is alive or not with no output
    """
    response_time = ping(host_ip, timeout=timeout)
    if response_time is not None:
        return True
    else: 
        return False
    
async def icmp_ping_sweep(subnet: str, timeout: int, sem:int)-> list[str]:
    """
    Pings a whole subnet in parallel.
    Returns a list of hosts that responded
    """
    hosts = expand_cidr(subnet)  
    alive: list[str] = []
    semaphore = asyncio.Semaphore(sem)

    async def check(ip: str):
        async with semaphore:
            try:
                rtt = await asyncio.to_thread(ping, ip, timeout=timeout)
                if isinstance(rtt, (int, float)) and rtt > 0:
                    return ip
            except Exception:
                pass
        return None
    results = await asyncio.gather(*(check(ip) for ip in hosts))
    alive = [ip for ip in results if ip]
    alive.sort(key=lambda s: tuple(map(int, s.split("."))))
    return alive