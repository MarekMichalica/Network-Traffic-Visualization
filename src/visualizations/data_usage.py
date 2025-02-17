import matplotlib.pyplot as plt
from datetime import datetime

def plot_data_usage(filtered_packets):
    data_usage = filtered_packets["data_usage"]
    timestamps = [datetime.strptime(t, "%Y-%m-%d %H:%M:%S") for t in data_usage.keys()]
    data_sent = list(data_usage.values())

    plt.plot(timestamps, data_sent, marker="o", linestyle="-", color="b")
    plt.xlabel("Čas")
    plt.ylabel("Prenesené dáta (bajty)")
    plt.title("Prenesená dáta za čas")
    plt.xticks(rotation=45)
    plt.grid()
    plt.show()
