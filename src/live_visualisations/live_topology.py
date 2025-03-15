import json
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.animation import FuncAnimation

def plot_network_topology(json_file, max_nodes=20):
    fig, ax = plt.subplots(figsize=(8, 6))  # Smaller figure size

    def animate(i):
        ax.clear()

        # Load packet data
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                packets = data['packets']
        except Exception as e:
            print(f"Error pri načítaní JSON súboru: {e}")
            return

        # Create directed graph
        G = nx.DiGraph()

        # Track connection weight and protocol
        edge_weights = {}
        edge_protocols = {}

        # Add edges for each packet
        for packet in packets:
            src = packet['src_ip']
            dst = packet['dst_ip']
            protocol = packet.get('protocol', 'Unknown')

            edge = (src, dst)
            if edge in edge_weights:
                edge_weights[edge] += 1
            else:
                edge_weights[edge] = 1
                edge_protocols[edge] = protocol

        # Sort by weight and keep only top connections
        top_edges = sorted(edge_weights.items(), key=lambda x: x[1], reverse=True)[:max_nodes]

        # Add edges to graph
        for (src, dst), weight in top_edges:
            protocol = edge_protocols.get((src, dst), "Unknown")
            G.add_edge(src, dst, weight=weight, protocol=protocol)

        # If graph is too large, limit it
        if len(G.nodes) > max_nodes:
            # Keep the most connected nodes
            top_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
            nodes_to_keep = [node for node, degree in top_nodes]
            G = G.subgraph(nodes_to_keep)

        # Get positions using spring layout with fewer iterations
        pos = nx.spring_layout(G, seed=42, iterations=15)

        # Simplified node sizes - just two categories
        node_sizes = {}
        for node in G.nodes():
            connections = len(list(G.in_edges(node))) + len(list(G.out_edges(node)))
            node_sizes[node] = 100 if connections <= 2 else 200

        # Draw the graph with simplified styling
        nx.draw_networkx_nodes(G, pos,
                               node_color='lightblue',
                               node_size=[node_sizes[node] for node in G.nodes()],
                               alpha=0.7,
                               ax=ax)

        nx.draw_networkx_edges(G, pos,
                               width=1,
                               edge_color='gray',
                               alpha=0.6,
                               arrowsize=10,
                               connectionstyle='arc3,rad=0.1',
                               ax=ax)

        nx.draw_networkx_labels(G, pos, font_size=7, ax=ax)

        # Add only protocol names as edge labels
        edge_labels = {(u, v): G[u][v]['protocol'] for u, v in G.edges()}
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6,
                                     font_color='darkblue', alpha=0.7, ax=ax)

        ax.set_title('Sieťová topológia', fontsize=12)
        ax.axis('off')

        plt.tight_layout()

    # Create animation with cache_frame_data=False to save memory
    ani = FuncAnimation(fig, animate, interval=1000, cache_frame_data=False)
    plt.tight_layout()
    plt.show()

    return ani  # Return animation object to prevent garbage collection

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Graf spojení - topológia siete")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    plot_network_topology(args.json_file)