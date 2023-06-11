import socket
import queue
from enum import Enum
from threading import Thread
from app.ui import print_result_scan


class Status(Enum):
    OPEN = "OPEN"
    CLOSE = "CLOSE"


class Scanner:
    def __init__(self, timeout: float = 0.25, workers: int = 10):
        self._workers = workers
        self._threads = []
        self._is_running = False
        socket.setdefaulttimeout(timeout)

    def start(self, host: str, ports: list[int],
              scan_tcp: bool = True, scan_udp: bool = True):
        self._is_running = True
        self._setup_threads(host, ports, scan_tcp, scan_udp)
        self._start_threads()
        Thread(target=self._join_threads).start()

    def stop(self):
        self._is_running = False
        self._join_threads()

    def _setup_threads(self, host: str, ports: list[int],
                       scan_tcp: bool = True, scan_udp: bool = True):
        ports_queue = queue.Queue()
        for port in ports:
            ports_queue.put(port)
        self._threads = [
            Thread(target=self._scanning,
                   args=[host, ports_queue,
                         scan_tcp, scan_udp]) for _ in range(self._workers)]

    def _scanning(self, host: str, ports: queue.Queue,
                  scan_tcp: bool = True, scan_udp: bool = True):
        while self._is_running:
            try:
                port = ports.get(block=False)
            except queue.Empty:
                break

            res = [port, {}]

            if scan_tcp:
                res[1]['tcp'] = self._check_tcp_port(host, port)
            if scan_udp:
                res[1]['udp'] = self._check_udp_port(host, port)

            print_result_scan(res)

    def _check_tcp_port(self, host: str, port: int) -> (Status, str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((host, port))
            if result == 0:
                return Status.OPEN, self._define_protocol(sock)
        return Status.CLOSE, ''

    def _check_udp_port(self, host: str, port: int) -> (Status, str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(b'', (host, port))
                data, _ = sock.recvfrom(1024)
                protocol = self._define_protocol_by_data(data)
                return Status.OPEN, protocol
            except (socket.timeout, ConnectionResetError):
                return Status.CLOSE, ''

    def _start_threads(self):
        for thread in self._threads:
            thread.setDaemon(True)
            thread.start()

    def _join_threads(self):
        for thread in self._threads:
            thread.join()

    def _define_protocol(self, sock: socket.socket):
        protocol = ''
        try:
            sock.send(b'ping\r\n\r\n')
            data = sock.recv(1024)
            protocol = self._define_protocol_by_data(data)
        finally:
            return protocol

    @staticmethod
    def _define_protocol_by_data(data: bytes):
        if b'SMTP' in data:
            return 'SMTP'
        if b'POP3' in data:
            return 'POP3'
        if b'IMAP' in data:
            return 'IMAP'
        if b'HTTP' in data:
            return 'HTTP'
        return ''
