import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from datetime import datetime
from collections import defaultdict


def analyze_flows(filtered_packets, pcap_file):
    # Extract packets and organize by flows
    packets = filtered_packets.get("filtered_packets", [])

    # Group packets by bidirectional flow
    flows = defaultdict(list)
    for packet in packets:
        # Extract packet data
        src_ip = packet.get("src_ip", "N/A")
        dst_ip = packet.get("dst_ip", "N/A")
        protocol = packet.get("protocol", "N/A")
        src_port = packet.get("src_port", "N/A")
        dst_port = packet.get("dst_port", "N/A")
        timestamp = packet.get("timestamp", "")
        size = packet.get("size", 0)

        # Skip non-IP packets
        if src_ip == "N/A" or dst_ip == "N/A":
            continue

        # Create bidirectional flow key (sort IPs and ports)
        ips = sorted([src_ip, dst_ip])
        ports = sorted([src_port, dst_port])
        flow_key = (ips[0], ips[1], protocol, ports[0], ports[1])

        # Determine direction (1=forward, -1=reverse)
        direction = 1 if src_ip == ips[0] else -1

        # Parse timestamp
        try:
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            flows[flow_key].append((dt, size, direction))
        except ValueError:
            continue

    # Check if we have data
    if not flows:
        fig = plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, "Žiadne dáta o tokoch nie sú k dispozícii",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    # Sort flows by packet count and take top 5 (more focused approach)
    top_flows = sorted(flows.items(), key=lambda x: len(x[1]), reverse=True)[:5]

    # Create a single figure with two subplots in a more compact layout
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8),
                                   gridspec_kw={'height_ratios': [2, 1]})

    # Color map for protocols
    protocol_colors = {
        'TCP': 'blue', 'UDP': 'green', 'HTTP': 'red',
        'HTTPS': 'purple', 'DNS': 'orange', 'ICMP': 'brown'
    }

    # Find time range for all packets
    all_times = [dt for _, flow_data in top_flows for dt, _, _ in flow_data]
    if not all_times:
        plt.close(fig)
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, "Žiadne platné časové údaje",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    min_time, max_time = min(all_times), max(all_times)

    # Prepare for plotting
    y_labels = []
    flow_stats = []

    # Plot each flow
    for i, (flow_key, packets_in_flow) in enumerate(top_flows):
        src_ip, dst_ip, protocol, src_port, dst_port = flow_key

        # Create simplified flow label
        flow_label = f"{src_ip.split('.')[-1]}:{src_port} ↔ {dst_ip.split('.')[-1]}:{dst_port}"
        y_labels.append(flow_label)
        y_pos = len(top_flows) - i

        # Get color for this protocol
        color = protocol_colors.get(protocol, 'darkgray')

        # Calculate packet volume and count
        packet_count = len(packets_in_flow)
        data_volume = sum(size for _, size, _ in packets_in_flow) / 1024  # KB
        flow_stats.append((flow_label, packet_count, data_volume))

        # Group packets by direction for more efficient plotting
        forward_packets = [(dt, size) for dt, size, dir in packets_in_flow if dir > 0]
        reverse_packets = [(dt, size) for dt, size, dir in packets_in_flow if dir < 0]

        # Plot forward and reverse packets
        if forward_packets:
            f_times, f_sizes = zip(*forward_packets)
            f_sizes = [max(20, min(80, s / 30)) for s in f_sizes]  # Scale sizes
            ax1.scatter(f_times, [y_pos] * len(f_times), s=f_sizes,
                        color=color, marker='^', alpha=0.7)

        if reverse_packets:
            r_times, r_sizes = zip(*reverse_packets)
            r_sizes = [max(20, min(80, s / 30)) for s in r_sizes]  # Scale sizes
            ax1.scatter(r_times, [y_pos] * len(r_times), s=r_sizes,
                        color=color, marker='v', alpha=0.7)

    # Configure timeline axis
    ax1.set_yticks(range(1, len(top_flows) + 1))
    ax1.set_yticklabels(y_labels[::-1])
    ax1.grid(True, axis='x', linestyle='--', alpha=0.5)
    ax1.set_title("Časová os toku paketov")

    # Set reasonable x-axis limits
    time_span = max_time - min_time
    padding = time_span * 0.05
    ax1.set_xlim(min_time - padding, max_time + padding)

    # Format x-axis based on time span
    if time_span.total_seconds() < 3600:  # Less than an hour
        formatter = mdates.DateFormatter('%H:%M:%S')
        locator = mdates.MinuteLocator(interval=1)
    else:  # More than an hour
        formatter = mdates.DateFormatter('%H:%M')
        locator = mdates.HourLocator(interval=1)

    ax1.xaxis.set_major_formatter(formatter)
    ax1.xaxis.set_major_locator(locator)
    plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')

    # Add legend for directionality
    ax1.scatter([], [], s=50, marker='^', color='gray', label="Vpred")
    ax1.scatter([], [], s=50, marker='v', color='gray', label="Spätne")
    ax1.legend(loc='upper right')

    # Create dual bar chart for statistics
    labels, packet_counts, data_volumes = zip(*flow_stats)
    x = np.arange(len(labels))
    width = 0.35

    # Use a shared axis with two different scales
    ax2.bar(x - width / 2, packet_counts, width, color='steelblue', label="Počet paketov")
    ax2.set_ylabel("Počet paketov", color='steelblue')
    ax2.tick_params(axis='y', labelcolor='steelblue')

    # Add data volume on secondary y-axis
    ax3 = ax2.twinx()
    ax3.bar(x + width / 2, data_volumes, width, color='darkorange', label="Objem dát (KB)")
    ax3.set_ylabel("Objem dát (KB)", color='darkorange')
    ax3.tick_params(axis='y', labelcolor='darkorange')

    # Set x-axis labels and title
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=45, ha='right')
    ax2.set_xlabel("Tok")
    ax2.set_title("Štatistika tokov")

    # Combine legends
    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax3.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

    # Add overall title with file name
    fig.suptitle(f"Analýza tokov - {pcap_file.split('/')[-1]}",
                 fontsize=14)

    # Make layout more compact
    plt.tight_layout()
    plt.subplots_adjust(top=0.92)

    # Display the plot
    plt.show()