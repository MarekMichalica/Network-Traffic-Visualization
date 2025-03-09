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
            sorted_protocols.append(('Other', other_count))

    # Prepare data for plotting
    labels = [protocol for protocol, _ in sorted_protocols]
    counts = [count for _, count in sorted_protocols]

    # Calculate percentages
    total = sum(counts)
    percentages = [(count / total) * 100 for count in counts]

    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 7))

    # Create bar chart
    ax1.bar(labels, counts, color='steelblue')
    ax1.set_title('Protocol Distribution')
    ax1.set_xlabel('Protocol')
    ax1.set_ylabel('Number of Packets')
    plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')

    # Add count labels on top of each bar
    for i, count in enumerate(counts):
        ax1.text(i, count + (max(counts) * 0.01), str(count), ha='center')

    # Create pie chart
    colors = plt.cm.tab10.colors
    if len(sorted_protocols) > 10:
        colors = list(colors) + ['gray']  # Add color for 'Other'

    ax2.pie(counts, labels=[f"{label} ({percentage:.1f}%)" for label, percentage in zip(labels, percentages)],
            autopct='', startangle=90, colors=colors)
    ax2.set_title('Protocol Distribution (%)')
    ax2.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle

    # Add file name to the overall title
    file_name = os.path.basename(pcap_file)
    plt.suptitle(f"Protocol Analysis - {file_name}", fontsize=16)

    plt.tight_layout()
    plt.subplots_adjust(top=0.9)
    plt.show()