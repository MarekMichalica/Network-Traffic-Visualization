def match_ip(packet, filters):
    src_ip = filters.get("src_ip")
    dst_ip = filters.get("dst_ip")

    if src_ip and packet.haslayer("IP") and packet["IP"].src != src_ip:
        return False
    if dst_ip and packet.haslayer("IP") and packet["IP"].dst != dst_ip:
        return False
    return True
