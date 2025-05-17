import matplotlib.pyplot as plt
from collections import Counter

def plot_port_distribution(filtered_packets, pcap_file=None):
    packets = filtered_packets["filtered_packets"]

    src_ports = [packet["src_port"] for packet in packets if "src_port" in packet]
    dst_ports = [packet["dst_port"] for packet in packets if "dst_port" in packet]

    src_port_counter = Counter(src_ports)
    dst_port_counter = Counter(dst_ports)

    top_src_ports = dict(src_port_counter.most_common(10))
    top_dst_ports = dict(dst_port_counter.most_common(10))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 7))

    ax1.bar(top_src_ports.keys(), top_src_ports.values(), color='skyblue')
    ax1.set_title('Najčastejšie zdrojové porty', fontsize=14)
    ax1.set_xlabel('Port', fontsize=12)
    ax1.set_ylabel('Počet výskytov', fontsize=12)
    ax1.tick_params(axis='x', rotation=45)
    ax1.grid(axis='y', linestyle='--', alpha=0.7)

    ax2.bar(top_dst_ports.keys(), top_dst_ports.values(), color='salmon')
    ax2.set_title('Najčastejšie cieľové porty', fontsize=14)
    ax2.set_xlabel('Port', fontsize=12)
    ax2.set_ylabel('Počet výskytov', fontsize=12)
    ax2.tick_params(axis='x', rotation=45)
    ax2.grid(axis='y', linestyle='--', alpha=0.7)

    title = 'Distribúcia portov'
    if pcap_file:
        title += f' - {pcap_file}'
    fig.suptitle(title, fontsize=16)

    plt.tight_layout()
    plt.subplots_adjust(top=0.9)

    total_src_ports = len(set(src_ports))
    total_dst_ports = len(set(dst_ports))
    info_text = f'Celkový počet unikátnych zdrojových portov: {total_src_ports}\n'
    info_text += f'Celkový počet unikátnych cieľových portov: {total_dst_ports}'

    plt.figtext(0.5, 0.01, info_text, ha='center', fontsize=10, bbox=dict(facecolor='#f0f0f0', alpha=0.5))
    plt.show()
