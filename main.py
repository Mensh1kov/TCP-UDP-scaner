from app.scanner import Scanner
from app.ui import parse_arguments


def parse_ports(ports: str) -> list:
    if ports == 'all':
        ports = '1-65535'

    ranges = (x.split("-") for x in ports.split(","))
    return [_ for r in ranges for _ in range(int(r[0]), int(r[-1]) + 1)]


def main():
    args = parse_arguments()
    ports = parse_ports(args.ports)
    scanner = Scanner()

    if not (args.tcp_scan or args.udp_scan):
        scanner.start(args.host, ports, True, False)
    else:
        scanner.start(args.host, ports, args.tcp_scan, args.udp_scan)


if __name__ == "__main__":
    main()
