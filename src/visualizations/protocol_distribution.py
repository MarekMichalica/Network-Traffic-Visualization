import matplotlib.pyplot as plt

def plot_protocols(protocol_counts):
    labels = protocol_counts.keys()
    sizes = protocol_counts.values()

    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
    plt.title("Protocol Usage in PCAP File")
    plt.show()
