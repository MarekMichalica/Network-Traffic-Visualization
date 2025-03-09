import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import os

from datetime import datetime
from collections import defaultdict


def plot_flow_analysis(filtered_packets, pcap_file):
    # Extract packet data
    packets = filtered_packets["filtered_packets"]

    # Group packets by flow (source IP, destination IP, protocol)
    flows = defaultdict(list)
    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        protocol = packet["protocol"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        timestamp = packet["timestamp"]
        size = packet["size"]

        # Skip non-IP packets
        if src_ip == "N/A" or dst_ip == "N/A":
            continue

        # Group by bidirectional flow (sort IPs and ports to group both directions)
        ips = sorted([src_ip, dst_ip])
        ports = sorted([src_port, dst_port])
        flow_key = (ips[0], ips[1], protocol, ports[0], ports[1])

        direction = 1 if src_ip == ips[0] else -1  # Direction: 1 = forward, -1 = reverse

        # Parse timestamp
        try:
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            flows[flow_key].append((dt, size, direction))
        except ValueError:
            continue  # Skip invalid timestamps

    # Check if we have flow data
    if not flows:
        plt.figure(figsize=(12, 8))
        plt.text(0.5, 0.5, "No flow data available",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    # Sort flows by total packet count (descending)
    sorted_flows = sorted(flows.items(), key=lambda x: len(x[1]), reverse=True)

    # Take top 10 flows
    top_flows = sorted_flows[:10] if len(sorted_flows) > 10 else sorted_flows

    # Create subplots - one for timeline and one for flow statistics
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 12), gridspec_kw={'height_ratios': [3, 1]})

    # Define colors for different protocols
    protocol_colors = {
        'TCP': 'blue',
        'UDP': 'green',
        'HTTP': 'red',
        'HTTPS': 'purple',
        'DNS': 'orange',
        'ICMP': 'brown',
        'DHCP': 'pink',
        'ARP': 'gray'
    }

    # Default color for unknown protocols
    default_color = 'darkgray'

    # Plot flow timeline
    y_positions = {}
    y_labels = []

    # Find overall time range
    all_times = []
    for flow_key, packets_in_flow in top_flows:
        for dt, _, _ in packets_in_flow:
            all_times.append(dt)

    if not all_times:
        plt.close(fig)
        plt.figure(figsize=(12, 8))
        plt.text(0.5, 0.5, "No valid timestamp data available",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    min_time = min(all_times)
    max_time = max(all_times)

    # Plot each flow
    for i, (flow_key, packets_in_flow) in enumerate(top_flows):
        src_ip, dst_ip, protocol, src_port, dst_port = flow_key

        # Create a label for this flow
        flow_label = f"{src_ip}:{src_port} ↔ {dst_ip}:{dst_port} ({protocol})"
        y_labels.append(flow_label)
        y_pos = len(top_flows) - i
        y_positions[flow_key] = y_pos

        # Get color for this protocol
        color = protocol_colors.get(protocol, default_color)

        # Sort packets by timestamp
        packets_in_flow.sort(key=lambda x: x[0])

        # Plot each packet in the flow
        for dt, size, direction in packets_in_flow:
            # Scale marker size by packet size
            marker_size = max(20, min(100, size / 20))  # Clamp between 20 and 100

            # Use triangle markers pointing up/down for direction
            marker = '^' if direction > 0 else 'v'

            ax1.scatter(dt, y_pos, s=marker_size, color=color,
                        marker=marker, alpha=0.7, edgecolors='black', linewidth=0.5)

    # Configure timeline axis
    ax1.set_yticks(range(1, len(top_flows) + 1))
    ax1.set_yticklabels(y_labels[::-1])
    ax1.grid(True, axis='x', linestyle='--', alpha=0.7)
    ax1.set_title('Packet Flow Timeline')

    # Set reasonable x-axis limits and format
    time_span = max_time - min_time
    padding = time_span * 0.05  # 5% padding on each side
    ax1.set_xlim(min_time - padding, max_time + padding)

    # Format x-axis to show appropriate time units
    if time_span.total_seconds() < 60:  # Less than a minute
        date_format = '%H:%M:%S'
        locator = mdates.SecondLocator(interval=5)
    elif time_span.total_seconds() < 3600:  # Less than an hour
        date_format = '%H:%M:%S'
        locator = mdates.MinuteLocator(interval=1)
    elif time_span.total_seconds() < 86400:  # Less than a day
        date_format = '%H:%M'
        locator = mdates.HourLocator(interval=1)
    else:  # More than a day
        date_format = '%Y-%m-%d %H:%M'
        locator = mdates.HourLocator(interval=6)

    formatter = mdates.DateFormatter(date_format)
    ax1.xaxis.set_major_formatter(formatter)
    ax1.xaxis.set_major_locator(locator)
    plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')

    # Add legend for directionality
    ax1.scatter([], [], s=50, marker='^', color='gray', label='→ Forward')
    ax1.scatter([], [], s=50, marker='v', color='gray', label='← Reverse')
    ax1.legend(loc='upper right')

    # Plot flow statistics in the second subplot
    flow_packet_counts = []
    flow_data_volumes = []
    flow_labels_for_bars = []

    for flow_key, packets_in_flow in top_flows:
        src_ip, dst_ip, protocol, src_port, dst_port = flow_key

        # Count total packets and data volume
        packet_count = len(packets_in_flow)
        data_volume = sum(size for _, size, _ in packets_in_flow) / 1024  # KB

        flow_packet_counts.append(packet_count)
        flow_data_volumes.append(data_volume)

        # Use shorter labels for bars
        short_label = f"{src_ip.split('.')[-1]}:{src_port} ↔ {dst_ip.split('.')[-1]}:{dst_port}"
        flow_labels_for_bars.append(short_label)

    # Create a dual-axis bar chart
    color1 = 'steelblue'
    color2 = 'darkorange'

    # Plot packet counts on left axis
    ax2_left = ax2
    bars1 = ax2_left.bar(flow_labels_for_bars, flow_packet_counts, color=color1, alpha=0.7, label='Packets')
    ax2_left.set_xlabel('Flow')
    ax2_left.set_ylabel('Packet Count', color=color1)
    ax2_left.tick_params(axis='y', labelcolor=color1)
    plt.setp(ax2_left.get_xticklabels(), rotation=45, ha='right')

    # Add data labels to bars
    for bar in bars1:
        height = bar.get_height()
        ax2_left.text(bar.get_x() + bar.get_width() / 2., height + 0.1,
                      f"{int(height)}",
                      ha='center', va='bottom', color=color1)

    # Create right y-axis for data volume
    ax2_right = ax2.twinx()
    bars2 = ax2_right.bar([x + 0.3 for x in range(len(flow_labels_for_bars))],
                          flow_data_volumes, color=color2, alpha=0.7, width=0.3, label='Data Volume')
    ax2_right.set_ylabel('Data Volume (KB)', color=color2)
    ax2_right.tick_params(axis='y', labelcolor=color2)

    # Add data labels to bars
    for bar in bars2:
        height = bar.get_height()
        ax2_right.text(bar.get_x() + bar.get_width() / 2., height + 0.1,
                       f"{height:.1f}",
                       ha='center', va='bottom', color=color2)

    # Add legend
    lines1, labels1 = ax2_left.get_legend_handles_labels()
    lines2, labels2 = ax2_right.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

    ax2.set_title('Flow Statistics')
    ax2.grid(axis='y', linestyle='--', alpha=0.3)

    # Add file name to the overall title
    file_name = os.path.basename(pcap_file)
    plt.suptitle(f"Flow Analysis - {file_name}", fontsize=16)

    plt.tight_layout()
    plt.subplots_adjust(top=0.95)
    plt.show()