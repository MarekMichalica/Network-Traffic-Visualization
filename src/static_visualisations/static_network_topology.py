import matplotlib.pyplot as plt
import networkx as nx
from collections import Counter
import os

def plot_network_topology(filtered_packets, pcap_file):
    # Extract packet data
    packets = filtered_packets["filtered_packets"]

    # Create a directed graph
    G = nx.DiGraph()

    # Count connections between source and destination
    connection_counts = Counter()
    port_protocols = {}
    data_volume = Counter()

    # Process each packet to build the graph
    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        protocol = packet["protocol"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        size = packet["size"]

        # Skip non-IP packets
        if src_ip == "N/A" or dst_ip == "N/A":
            continue

        # Create nodes if they don't exist
        if src_ip not in G:
            G.add_node(src_ip)
        if dst_ip not in G:
            G.add_node(dst_ip)

        # Count connections and accumulate data volume
        connection_key = (src_ip, dst_ip)
        connection_counts[connection_key] += 1
        data_volume[connection_key] += size

        # Store protocol and port info
        port_protocols[(src_ip, dst_ip)] = (protocol, src_port, dst_port)

    # Add weighted edges based on connection counts
    for (src, dst), count in connection_counts.items():
        # Get protocol and port info
        protocol, src_port, dst_port = port_protocols.get((src, dst), ("Unknown", "N/A", "N/A"))
        volume = data_volume[(src, dst)]

        # Create edge with attributes
        G.add_edge(src, dst,
                   weight=count,
                   volume=volume,
                   protocol=protocol,
                   src_port=src_port,
                   dst_port=dst_port)

    # Check if graph is empty
    if len(G.nodes()) == 0:
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, "No network topology data available",
                 horizontalalignment='center', fontsize=14)
        plt.tight_layout()
        plt.show()
        return

    # Create the plot
    plt.figure(figsize=(14, 10))

    # Node positions - using spring layout for automatic positioning
    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)

    # Determine node sizes based on activity (sum of in and out edges)
    node_sizes = {}
    for node in G.nodes():
        in_edges = sum(data['weight'] for _, _, data in G.in_edges(node, data=True))
        out_edges = sum(data['weight'] for _, _, data in G.out_edges(node, data=True))
        node_sizes[node] = 100 + (in_edges + out_edges) * 2  # Scale factor to make nodes visible

    node_size_values = [node_sizes[node] for node in G.nodes()]

    # Calculate edge widths based on connection count
    edge_widths = [G[u][v]['weight'] / 5 for u, v in G.edges()]

    # Prepare edge labels
    edge_labels = {}
    for u, v, data in G.edges(data=True):
        protocol = data['protocol']
        volume_kb = data['volume'] / 1024
        edge_labels[(u, v)] = f"{protocol}\n{data['weight']} pkts\n{volume_kb:.1f} KB"

    # Draw the graph components
    nx.draw_networkx_nodes(G, pos, node_size=node_size_values, node_color='skyblue', alpha=0.8)
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='grey',
                           connectionstyle='arc3,rad=0.1', arrowsize=15)

    # Draw labels with smaller font and wrapped to multiple lines if needed
    nx.draw_networkx_labels(G, pos, font_size=8, font_family='sans-serif')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7,
                                 font_family='sans-serif', bbox=dict(alpha=0.5))

    # Add a title
    file_name = os.path.basename(pcap_file)
    plt.title(f"Network Topology Graph - {file_name}", fontsize=16)

    # Remove axes
    plt.axis('off')

    # Add a legend for node sizes
    plt.figtext(0.01, 0.01, "Node size indicates activity level (number of connections)",
                fontsize=10, ha='left')

    plt.tight_layout()
    plt.show()