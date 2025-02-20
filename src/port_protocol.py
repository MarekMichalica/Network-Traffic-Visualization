protocol_map = {
    6: "TCP",  # TCP
    17: "UDP",  # UDP
    1: "ICMP",  # ICMP
    2: "IGMP",  # IGMP (Internet Group Management Protocol)
    41: "IPv6",  # IPv6 encapsulated in IPv4
    58: "ICMPv6",  # ICMPv6
    50: "ESP",  # Encapsulating Security Payload (ESP)
    51: "AH",  # Authentication Header (AH)
    89: "OSPF",  # OSPF (Open Shortest Path First)
}

# Mapovanie portov na protokoly
port_to_protocol = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    6: "TCP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    465: "SMTPS",
    514: "Syslog",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}

# Predvolený protokol pre neznáme porty
default_protocol = "Unknown"

def get_protocol_by_ip_proto(ip_proto):
    """Získaj protokol na základe čísla protokolu IP."""
    return protocol_map.get(ip_proto, "Unknown")  # Ak nie je protokol nájdený, vráti "Unknown"

def get_protocol_by_port(port):
    """Získaj protokol na základe portu."""
    return port_to_protocol.get(port, "Unknown")

def map_tcp_flags(flags):
    flag_mapping = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR"
    }
    return [flag_mapping.get(flag, flag) for flag in flags]