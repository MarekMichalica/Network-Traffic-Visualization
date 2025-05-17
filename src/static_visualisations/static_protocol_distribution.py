import matplotlib.pyplot as plt
import os

def plot_protocols(protocol_counts, pcap_file):
    # Sort protocols by count in descending order
    sorted_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)

    # Take top 10 protocols if there are more than 10
    if len(sorted_protocols) > 10:
        other_count = sum(count for protocol, count in sorted_protocols[10:])
        sorted_protocols = sorted_protocols[:10]
        if other_count > 0:
            sorted_protocols.append(('Ostatné', other_count))

    # Prepare data for plotting
    labels = [protocol for protocol, count in sorted_protocols]
    counts = [count for protocol, count in sorted_protocols]

    # Create figure with a single subplot
    fig, ax1 = plt.subplots(figsize=(8, 5))

    # Create bar chart
    ax1.bar(labels, counts, color='steelblue')
    ax1.set_title('Distribúcia protokolov')
    ax1.set_xlabel('Protokol')
    ax1.set_ylabel('Počet paketov')
    plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')

    # Add count labels on top of each bar
    for i, count in enumerate(counts):
        ax1.text(i, count + (max(counts) * 0.01), str(count), ha='center')

    # Add file name to the overall title
    file_name = os.path.basename(pcap_file)
    plt.suptitle(f"Analýza protokolov - {file_name}", fontsize=14)

    plt.tight_layout()
    plt.subplots_adjust(top=0.88)
    plt.show()
