import json
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import defaultdict

def plot_flow_analysis(json_file):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 10))

    def animate(i):
        ax1.clear()
        ax2.clear()

        # Load packet data
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                packets = data['packets']
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            return

        # Group packets by flow (src_ip, dst_ip, src_port, dst_port, protocol)
        flows = defaultdict(list)
        for packet in packets:
            flow_key = (
                packet.get('src_ip', 'unknown'),
                packet.get('dst_ip', 'unknown'),
                packet.get('src_port', 'unknown'),
                packet.get('dst_port', 'unknown'),
                packet.get('protocol', 'unknown')
            )
            flows[flow_key].append(packet)

        # Calculate flow statistics
        flow_stats = []
        for flow_key, flow_packets in flows.items():
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key

            # Calculate statistics
            packet_count = len(flow_packets)
            total_bytes = sum(packet.get('size', 0) for packet in flow_packets)

            # Get first and last packet timestamps
            timestamps = [packet.get('timestamp', '00:00:00') for packet in flow_packets]

            # Create flow info
            flow_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_count': packet_count,
                'total_bytes': total_bytes,
                'flow_id': f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})"
            }
            flow_stats.append(flow_info)

        # Sort by total bytes
        flow_stats.sort(key=lambda x: x['total_bytes'], reverse=True)

        # Top 10 flows by bytes
        top_flows = flow_stats[:10]

        # Plot top flows
        if top_flows:
            flow_ids = [flow['flow_id'] for flow in top_flows]
            total_bytes = [flow['total_bytes'] for flow in top_flows]
            packet_counts = [flow['packet_count'] for flow in top_flows]

            # Plot bytes
            ax1.barh(flow_ids, total_bytes, color='skyblue')
            ax1.set_title('Top 10 tokov podľa objemu dát')
            ax1.set_xlabel('Celkový objem (bajty)')

            # Plot packet counts
            ax2.barh(flow_ids, packet_counts, color='lightgreen')
            ax2.set_title('Top 10 tokov podľa počtu paketov')
            ax2.set_xlabel('Počet paketov')
        else:
            ax1.text(0.5, 0.5, "Žiadne dáta k zobrazeniu", ha='center', va='center')
            ax2.text(0.5, 0.5, "Žiadne dáta k zobrazeniu", ha='center', va='center')

        plt.tight_layout()

    # Create animation
    ani = FuncAnimation(fig, animate, interval=1000)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analýza tokov")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    plot_flow_analysis(args.json_file)