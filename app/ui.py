import argparse

PATTERN = "{}: {}"
PATTERN_WITH_PROTOCOL = "{}: {}\{}"
PATTERN_RESULT = "{:5}  {:15}  {:15}"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-t',
        action='store_true',
        dest='tcp_scan',
        help='the program will scan tcp ports.')

    parser.add_argument(
        '-u',
        action='store_true',
        dest='udp_scan',
        help='the program will scan udp ports.')

    parser.add_argument(
        '-p', '--ports',
        default='1-1024',
        help='this port range will be scanned.')

    parser.add_argument('host', help='this host will be scanned.')

    return parser.parse_args()


def print_result_scan(result: list):
    port = result[0]
    info = result[1]
    out = [str(port)]

    for tr_protocol, info in info.items():
        status, protocol = info

        if protocol:
            out.append(PATTERN_WITH_PROTOCOL.format(
                tr_protocol, status.value, protocol))
        else:
            out.append(PATTERN.format(tr_protocol, status.value))

    print(PATTERN_RESULT.format(*out, ''))
