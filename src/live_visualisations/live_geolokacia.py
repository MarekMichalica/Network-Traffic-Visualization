import json
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import geoip2.database
import cartopy.crs as ccrs
import cartopy.feature as cfeature
from collections import Counter
import os

def plot_ip_geolocation(json_file):
    # Check if GeoLite2 database exists
    db_path = 'GeoLite2-City.mmdb'
    if not os.path.exists(db_path):
        print(f"Error: GeoLite2 database not found at {db_path}")
        print("Please download the GeoLite2 City database from MaxMind and place it in the current directory.")
        print("Visit: https://dev.maxmind.com/geoip/geoip2/geolite2/")
        return

    # Create figure with a map
    fig = plt.figure(figsize=(12, 8))
    ax = fig.add_subplot(1, 1, 1, projection=ccrs.PlateCarree())

    # Add map features
    ax.add_feature(cfeature.COASTLINE)
    ax.add_feature(cfeature.BORDERS, linestyle=':')
    ax.add_feature(cfeature.LAND, facecolor='lightgray')
    ax.add_feature(cfeature.OCEAN, facecolor='lightblue')

    def animate(i):
        # Clear previous points
        for collection in ax.collections:
            collection.remove()

        # Load packet data
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                packets = data['packets']
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            return

        # Open GeoIP database
        try:
            reader = geoip2.database.Reader(db_path)
        except Exception as e:
            print(f"Error opening GeoIP database: {e}")
            return

        # Extract unique IPs
        all_ips = set()
        for packet in packets:
            all_ips.add(packet.get('src_ip', 'unknown'))
            all_ips.add(packet.get('dst_ip', 'unknown'))

        # Filter out private IP addresses
        public_ips = [ip for ip in all_ips if not (
                ip.startswith('10.') or
                ip.startswith('172.16.') or
                ip.startswith('192.168.') or
                ip == '127.0.0.1' or
                ip == 'unknown'
        )]

        # Count packets per IP
        ip_counter = Counter()
        for packet in packets:
            src_ip = packet.get('src_ip', 'unknown')
            dst_ip = packet.get('dst_ip', 'unknown')

            if src_ip in public_ips:
                ip_counter[src_ip] += 1
            if dst_ip in public_ips:
                ip_counter[dst_ip] += 1

        # Get locations
        locations = []
        for ip in public_ips:
            try:
                response = reader.city(ip)
                if response.location.latitude and response.location.longitude:
                    count = ip_counter[ip]
                    locations.append({
                        'ip': ip,
                        'lat': response.location.latitude,
                        'lon': response.location.longitude,
                        'country': response.country.name,
                        'city': response.city.name,
                        'count': count
                    })
            except Exception:
                # Skip IPs that can't be geolocated
                continue

        if not locations:
            ax.text(0, 0, "Žiadne verejné IP adresy k zobrazeniu alebo problém s geolokáciou",
                    ha='center', va='center', transform=ccrs.PlateCarree())
            return

        # Extract coordinates and counts
        lons = [loc['lon'] for loc in locations]
        lats = [loc['lat'] for loc in locations]
        counts = [loc['count'] for loc in locations]

        # Normalize counts for marker size
        min_size = 20
        max_size = 200
        if max(counts) > min(counts):
            norm_counts = [min_size + (c - min(counts)) * (max_size - min_size) / (max(counts) - min(counts)) for c in counts]
        else:
            norm_counts = [min_size for _ in counts]

        # Plot points
        sc = ax.scatter(lons, lats, s=norm_counts, c=counts, cmap='viridis',
                        transform=ccrs.PlateCarree(), alpha=0.7, edgecolor='black')

        # Add colorbar
        if len(fig.axes) == 1:  # If colorbar doesn't exist yet
            cbar = plt.colorbar(sc, ax=ax, pad=0.01)
            cbar.set_label('Počet paketov')

        # Set title
        ax.set_title('Geolokácia IP adries')
        ax.set_global()  # Show the whole world

        plt.tight_layout()

    # Create animation
    ani = FuncAnimation(fig, animate, interval=1000)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Geolokácia IP adries")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    plot_ip_geolocation(args.json_file)