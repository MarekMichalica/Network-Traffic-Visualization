import json
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.animation import FuncAnimation

def plot_network_topology(json_file, max_nodes=20):
    """
    Plot a network topology graph showing connections between devices.

    Args:
        json_file (str): Path to the JSON file containing packet data
        max_nodes (int): Maximum number of nodes to display
    """
    fig, ax = plt.subplots(figsize=(10, 8))

    def animate(i):
        ax.clear()

        # Load packet data
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                packets = data['packets']
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            return

        # Create directed graph
        G = nx.DiGraph()

        # Track connection weight
        edge_weights = {}

        # Add edges for each packet
        for packet in packets:
            src = packet['src_ip']
            dst = packet['dst_ip']

            edge = (src, dst)
            if edge in edge_weights:
                edge_weights[edge] += 1
            else:
                edge_weights[edge] = 1

        # Sort by weight and keep only top connections
        top_edges = sorted(edge_weights.items(), key=lambda x: x[1], reverse=True)[:max_nodes]

        # Add edges to graph
        for (src, dst), weight in top_edges:
            G.add_edge(src, dst, weight=weight)

        # If graph is too large, limit it
        if len(G.nodes) > max_nodes:
            # Keep the most connected nodes
            top_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
            nodes_to_keep = [node for node, _ in top_nodes]
            G = G.subgraph(nodes_to_keep)

        # Get positions using spring layout
        pos = nx.spring_layout(G, seed=42)

        # Get edge weights for line thickness
        edges = G.edges()
        weights = [G[u][v]['weight'] for u, v in edges]

        # Normalize weights for better visualization
        if weights:
            max_weight = max(weights)
            normalized_weights = [1 + 5 * (w / max_weight) for w in weights]
        else:
            normalized_weights = []

        # Draw the graph
        nx.draw_networkx_nodes(G, pos, node_color='skyblue', node_size=500, alpha=0.8, ax=ax)
        nx.draw_networkx_edges(G, pos, width=normalized_weights, edge_color='gray',
                               arrowsize=15, connectionstyle='arc3,rad=0.1', ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=8, ax=ax)

        # Add edge labels (packet counts)
        edge_labels = {(u, v): f"{G[u][v]['weight']}" for u, v in G.edges()}
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, ax=ax)

        ax.set_title('Graf spojení - topológia siete')
        ax.axis('off')

        plt.tight_layout()

    # Create animation
    ani = FuncAnimation(fig, animate, interval=1000)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Graf spojení - topológia siete")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    plot_network_topology(args.json_file)