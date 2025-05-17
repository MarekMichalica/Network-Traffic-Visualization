import re
import matplotlib.pyplot as plt
import numpy as np
import mplcursors  # pip install mplcursors

def plot_s7_functions(packet_data):
    # Count function codes from S7COMM packets
    function_counts = {}

    for packet in packet_data:
        if packet.get('protocol', '').upper() == 'S7COMM':
            payload = packet.get('payload', '')
            match = re.search(r'Code: (\d+)', payload)
            if match:
                code = match.group(1)
                function_counts[code] = function_counts.get(code, 0) + 1

    if not function_counts:
        print("Žiadne dostupné S7 funkcie")
        return

    # Function descriptions
    function_descriptions = {
        '4': 'Čítanie premennej',
        '5': 'Zápis premennej',
        '0': 'Nadviazanie spojenia',
        '1': 'Zistenie pripojenia',
        '3': 'Ukončenie spojenia',
        '7': 'Čítanie/zápis viacerých premenných',
        '240': 'PDU - začiatok prenosu',
        '241': 'PDU - koniec prenosu',
        '28': 'Ovládanie PLC',
        '29': 'Nahrávanie blokov',
        '30': 'Sťahovanie blokov',
        '31': 'Spustenie/zastavenie PLC',
        '242': 'Diagnostika',
        '243': 'Čítanie diagnostiky'
    }

    # Categories mapping
    function_categories = {
        'read': ['4', '7', '243'],
        'write': ['5', '7', '29', '30'],
        'control': ['0', '1', '3', '28', '31'],
        'other': ['240', '241', '242']
    }

    category_data = {
        'Čítanie': 0,
        'Zápis': 0,
        'Riadenie': 0,
        'Ostatné': 0
    }

    for code, count in function_counts.items():
        if code in function_categories['read']:
            category_data['Čítanie'] += count
        elif code in function_categories['write']:
            category_data['Zápis'] += count
        elif code in function_categories['control']:
            category_data['Riadenie'] += count
        else:
            category_data['Ostatné'] += count

    # Filter categories with counts > 0
    chart_data = {k: v for k, v in category_data.items() if v > 0}
    categories = list(chart_data.keys())
    counts = list(chart_data.values())

    # Colors matching your JS
    category_colors = {
        'Čítanie': '#4285F4',
        'Zápis': '#EA4335',
        'Riadenie': '#FBBC05',
        'Ostatné': '#34A853'
    }
    colors = [category_colors.get(cat, 'gray') for cat in categories]

    fig, ax = plt.subplots(figsize=(8, 5))

    bars = ax.bar(categories, counts, color=colors)

    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

    # Title and axis labels
    ax.set_title('Používané S7 funkcie – read/write', fontsize=14, fontweight='bold')
    ax.set_xlabel('Kategória funkcií')
    ax.set_ylabel('Počet výskytov')
    ax.set_ylim(0, max(counts) * 1.1)

    # Create tooltip text per category
    def create_function_list(category):
        if category == 'Čítanie':
            codes = function_categories['read']
        elif category == 'Zápis':
            codes = function_categories['write']
        elif category == 'Riadenie':
            codes = function_categories['control']
        else:
            codes = function_categories['other']

        items = []
        for c in codes:
            if c in function_counts:
                desc = function_descriptions.get(c, f'Funkcia {c}')
                items.append(f"{desc} ({function_counts[c]})")
        return "\n".join(items)

    # Use mplcursors for hover tooltip
    cursor = mplcursors.cursor(bars, hover=True)
    @cursor.connect("add")
    def on_add(sel):
        category = categories[sel.target.index]
        count = counts[sel.target.index]
        details = create_function_list(category)
        sel.annotation.set(text=f"{category} funkcií\nPočet: {count}\n\n{details}")
        sel.annotation.get_bbox_patch().set(fc="white")

    plt.tight_layout()
    plt.show()
