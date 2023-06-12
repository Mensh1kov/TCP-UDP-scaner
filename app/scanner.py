import socket
import queue
from enum import Enum
from threading import Thread
from app.ui import print_result_scan


class Status(Enum):
    OPEN = "OPEN"
    CLOSE = "CLOSE"


class Scanner:
    """
    Класс Scanner представляет собой утилиту для сканирования TCP и UDP портов на указанном хосте.
    """
    def __init__(self, timeout: float = 0.25, workers: int = 10):
        """
        Инициализирует объект Scanner.

        Args:
            timeout (float): Время ожидания для сокета в секундах (по умолчанию 0.25).
            workers (int): Количество потоков-обработчиков для распараллеливания сканирования (по умолчанию 10).
        """
        self._workers = workers
        self._threads = []
        self._is_running = False
        socket.setdefaulttimeout(timeout)

    def start(self, host: str, ports: list[int],
              scan_tcp: bool = True, scan_udp: bool = True):
        """
        Запускает сканирование портов на указанном хосте.

        Args:
            host (str): Хост, на котором будет производиться сканирование.
            ports (list[int]): Список портов, которые будут сканироваться.
            scan_tcp (bool): Флаг для сканирования портов TCP (по умолчанию True).
            scan_udp (bool): Флаг для сканирования портов UDP (по умолчанию True).
        """
        self._is_running = True
        self._setup_threads(host, ports, scan_tcp, scan_udp)
        self._start_threads()
        Thread(target=self._join_threads).start()

    def stop(self):
        """
        Останавливает сканирование портов.
        """
        self._is_running = False
        self._join_threads()

    def _setup_threads(self, host: str, ports: list[int],
                       scan_tcp: bool = True, scan_udp: bool = True):
        """
        Настройка потоков для сканирования портов.

        Args:
            host (str): Хост, на котором будет производиться сканирование.
            ports (list[int]): Список портов, которые будут сканироваться.
            scan_tcp (bool): Флаг для сканирования портов TCP (по умолчанию True).
            scan_udp (bool): Флаг для сканирования портов UDP (по умолчанию True).
        """
        ports_queue = queue.Queue()
        for port in ports:
            ports_queue.put(port)
        self._threads = [
            Thread(target=self._scanning,
                   args=[host, ports_queue,
                         scan_tcp, scan_udp]) for _ in range(self._workers)]

    def _scanning(self, host: str, ports: queue.Queue,
                  scan_tcp: bool = True, scan_udp: bool = True):
        """
        Метод, выполняемый в потоках для сканирования портов.

        Args:
            host (str): Хост, на котором будет производиться сканирование.
            ports (Queue): Очередь портов для сканирования.
            scan_tcp (bool): Флаг для сканирования портов TCP (по умолчанию True).
            scan_udp (bool): Флаг для сканирования портов UDP (по умолчанию True).
        """
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
        """
        Проверяет указанный TCP порт на указанном хосте.

        Args:
            host (str): Хост, на котором будет производиться проверка порта.
            port (int): Порт для проверки.

        Returns:
            (Status, str): Кортеж с состоянием порта (Status) и протоколом, если порт открыт.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((host, port))
            if result == 0:
                return Status.OPEN, self._define_protocol(sock)
        return Status.CLOSE, ''

    def _check_udp_port(self, host: str, port: int) -> (Status, str):
        """
        Проверяет указанный UDP порт на указанном хосте.

        Args:
            host (str): Хост, на котором будет производиться проверка порта.
            port (int): Порт для проверки.

        Returns:
            (Status, str): Кортеж с состоянием порта (Status) и протоколом, если порт открыт.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(b'', (host, port))
                data, _ = sock.recvfrom(1024)
                protocol = self._define_protocol_by_data(data)
                return Status.OPEN, protocol
            except (socket.timeout, ConnectionResetError):
                return Status.CLOSE, ''

    def _start_threads(self):
        """
        Запускает потоки для сканирования портов.
        """
        for thread in self._threads:
            thread.setDaemon(True)
            thread.start()

    def _join_threads(self):
        """
        Ожидает завершения всех потоков сканирования портов.
        """
        for thread in self._threads:
            thread.join()

    def _define_protocol(self, sock: socket.socket):
        """
        Определяет протокол, работающий на указанном сокете.

        Args:
            sock (socket.socket): Сокет, на котором будет производиться определение протокола.

        Returns:
            str: Название протокола (HTTP, SMTP, POP3, IMAP) или пустую строку, если протокол не определен.
        """
        protocol = ''
        try:
            sock.send(b'ping\r\n\r\n')
            data = sock.recv(1024)
            protocol = self._define_protocol_by_data(data)
        finally:
            return protocol

    @staticmethod
    def _define_protocol_by_data(data: bytes):
        """
        Определяет протокол по полученным данным.

        Args:
            data (bytes): Данные для определения протокола.

        Returns:
            str: Название протокола (HTTP, SMTP, POP3, IMAP) или пустую строку, если протокол не определен.
        """
        if b'SMTP' in data:
            return 'SMTP'
        if b'POP3' in data:
            return 'POP3'
        if b'IMAP' in data:
            return 'IMAP'
        if b'HTTP' in data:
            return 'HTTP'
        return ''
