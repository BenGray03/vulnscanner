import asyncio
import typer
from vulnscan.scan import tcp

app = typer.Typer(help="simple vulnerability tester")

@app.command()
def scanner(
    target: str = typer.Argument(..., help="Target host you want to scan"),
    ports: str = typer.Option("1-1024", help="Rnage or list of ports to scan. (-p- or - for all ports)"),
    timeout: int = typer.Option(2.5, help="Connection timeout"),
    semaphores: int = typer.Option(200, help="how many operations we can do in parallel.")
):
    print("running")
    result = asyncio.run(tcp.scan_host_tcp(target, ports, timeout, semaphores))
    print(result)


if __name__ == "__main__":
    app()