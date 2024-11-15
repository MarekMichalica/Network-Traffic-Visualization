import matplotlib.pyplot as plt

def plot_protocols(protocol_counts, pcap_file):
    labels = protocol_counts.keys()
    sizes = protocol_counts.values()

    fileLocation = pcap_file[5:]

    plt.figure(figsize=(9, 9))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
    plt.title("Protocol Usage in " + fileLocation)
    plt.show()
