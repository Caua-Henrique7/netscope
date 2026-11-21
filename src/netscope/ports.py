"""Interpretação de portas e nomes de serviços conhecidos"""

from __future__ import annotations

TOP_PORTS = (
    7, 20, 21, 22, 23, 25, 26, 37, 43, 53, 69, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    123, 135, 137, 139, 143, 161, 179, 389, 427, 443, 444, 445, 464, 465, 500, 512, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 636, 873, 990, 993, 995, 1025, 1080, 1099,
    1433, 1521, 1723, 1883, 2049, 2121, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 3632,
    4369, 4443, 4444, 4848, 5000, 5060, 5432, 5601, 5672, 5900, 5901, 5985, 5986, 6000,
    6379, 6443, 6667, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8088, 8161, 8443, 8500,
    8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250,
    11211, 15672, 27017, 50000,
)

SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2121: "ftp", 2375: "docker", 2376: "docker-tls",
    2379: "etcd", 3000: "http", 3128: "squid", 3306: "mysql", 3389: "rdp",
    4443: "https", 5000: "http", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5901: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis",
    6443: "kubernetes-api", 8000: "http", 8008: "http", 8080: "http", 8081: "http",
    8088: "http", 8443: "https", 8888: "http", 9000: "http", 9042: "cassandra",
    9090: "http", 9092: "kafka", 9200: "elasticsearch", 9443: "https",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    spec = spec.strip().lower()
    if spec in ("top", "default"):
        return list(TOP_PORTS)
    if spec in ("full", "all", "-"):
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "top":
            ports.update(TOP_PORTS)
            continue
        try:
            if "-" in part:
                low_text, high_text = part.split("-", 1)
                low, high = int(low_text), int(high_text)
            else:
                low = high = int(part)
        except ValueError:
            raise ValueError(f"especificação de porta invalida: '{part}'") from None
        if not (1 <= low <= high <= 65535):
            raise ValueError(f"porta fora do intervalo (1-65535): '{part}'")
        ports.update(range(low, high + 1))

    if not ports:
        raise ValueError("nenhuma porta especificada")
    return sorted(ports)