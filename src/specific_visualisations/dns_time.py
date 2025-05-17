import json
import random
import matplotlib.pyplot as plt

def plot_dns_time(data_input):
    packets = None
    if isinstance(data_input, str):
        try:
            with open(data_input, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    packets = loaded
                elif isinstance(loaded, dict):
                    if "packets" in loaded:
                        packets = loaded["packets"]
                    else:
                        print("Neplatný formát JSON: očakávaný kľúč 'packets'")
                        return
                else:
                    print("Neplatný formát JSON: očakávaný zoznam alebo slovník")
                    return
        except Exception as e:
            print(f"Chyba pri načítaní JSON: {e}")
            return
    elif isinstance(data_input, dict):
        if "packets" in data_input:
            packets = data_input["packets"]
        else:
            packets = [data_input]
    elif isinstance(data_input, list):
        packets = data_input
    else:
        print("Neplatný vstup pre DNS distribúciu času")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # Filter DNS responses and simulate response times
    dns_responses = []
    for packet in packets:
        if packet.get('protocol', '').upper() == 'DNS':
            payload = packet.get('payload', '')
            if 'Response' in payload:
                response_time = random.uniform(0, 500)
                dns_responses.append(response_time)

    if len(dns_responses) == 0:
        print("Žiadne dostupné DNS odpovede")
        return

    bin_size = 25
    max_response_time = max(dns_responses)
    bins = int(max_response_time // bin_size) + 1

    histogram_data = [0] * bins
    for time in dns_responses:
        bin_index = int(time // bin_size)
        histogram_data[bin_index] += 1

    time_ranges = [f"{i*bin_size}-{(i+1)*bin_size}" for i in range(bins)]

    # Plot
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(time_ranges, histogram_data, color='#4285F4')

    plt.xticks(rotation=45)

    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(f'{height}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 5),
                        textcoords="offset points",
                        ha='center', va='bottom')

    avg_time = sum(dns_responses) / len(dns_responses)
    avg_count = sum(histogram_data) / bins
    ax.axhline(y=avg_count, color='red', linestyle='--', linewidth=1)
    ax.text(bins - 1, avg_count + 0.5, f'Priemer: {avg_time:.1f} ms', color='red', ha='right')

    ax.set_title('Distribúcia času DNS odoziev', fontsize=14, fontweight='bold')
    ax.set_xlabel('Čas odozvy (ms)')
    ax.set_ylabel('Počet odpovedí')

    plt.tight_layout()
    plt.show()
