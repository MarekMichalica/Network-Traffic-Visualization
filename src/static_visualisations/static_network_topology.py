import matplotlib.pyplot as plt
import networkx as nx
from collections import Counter
import os

def plot_network_topology(filtered_packets, pcap_file):
    # Extract packet data
    packets = filtered_packets["filtered_packets"]

    # Create a directed graph
    G = nx.DiGraph()

    # Count connections and track protocols
    connection_counts = Counter()
    protocols = {}

    # Process each packet to build the graph
    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        protocol = packet["protocol"]

        # Skip non-IP packets
        if src_ip == "N/A" or dst_ip == "N/A":
            continue

        # Create nodes if they don't exist
        if src_ip not in G:
            G.add_node(src_ip)
        if dst_ip not in G:
            G.add_node(dst_ip)

        # Count connections and track protocol
        connection_key = (src_ip, dst_ip)
        connection_counts[connection_key] += 1
        protocols[connection_key] = protocol

    # Add edges based on connection counts
    for (src, dst), count in connection_counts.items():
        protocol = protocols.get((src, dst), "Unknown")
        G.add_edge(src, dst, weight=count, protocol=protocol)

    # Check if graph is empty
    if len(G.nodes()) == 0:
        plt.figure(figsize=(8, 4))
        plt.text(0.5, 0.5, "Žiadne dáta o sieťovej topológii nie sú k dispozícii",
                 horizontalalignment='center', fontsize=12)
        plt.tight_layout()
        plt.show()
        return

    plt.figure(figsize=(10, 6))

    # Node positions - using spring layout
    pos = nx.spring_layout(G, k=0.3, iterations=30, seed=42)

    node_sizes = {}
    for node in G.nodes():
        connections = len(list(G.in_edges(node))) + len(list(G.out_edges(node)))
        node_sizes[node] = 100 if connections <= 2 else 200

    # Draw the graph components - simplified
    nx.draw_networkx_nodes(G, pos, node_size=[node_sizes[node] for node in G.nodes()],
                           node_color='lightblue', alpha=0.7)
    nx.draw_networkx_edges(G, pos, width=1, alpha=0.6, edge_color='grey',
                           arrowsize=10)

    # Draw simplified labels
    nx.draw_networkx_labels(G, pos, font_size=7, font_family='sans-serif')

    # Draw only protocol names as edge labels
    edge_labels = {(u, v): data['protocol'] for u, v, data in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6,
                                 font_color='darkblue', alpha=0.7)

    # Add a title
    file_name = os.path.basename(pcap_file)
    plt.title(f"Sieťová topológia - {file_name}", fontsize=12)

    # Remove axes
    plt.axis('off')

    plt.tight_layout()
    plt.show()