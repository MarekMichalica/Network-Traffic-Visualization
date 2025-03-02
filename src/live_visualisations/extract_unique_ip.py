import json
import sys
from collections import Counter

def extract_unique_ips(json_file_path):
    """
    Extract unique IP addresses from a JSON file containing packet data.
    
    Args:
        json_file_path (str): Path to the JSON file
        
    Returns:
        tuple: Set of unique source IPs, Set of unique destination IPs, Set of all unique IPs
    """
    try:
        # Open and load the JSON file
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        
        # Check if 'packets' key exists
        if 'packets' not in data:
            print("Error: The JSON file does not contain a 'packets' key.")
            return set(), set(), set()
        
        # Extract source and destination IPs
        src_ips = set()
        dst_ips = set()
        
        for packet in data['packets']:
            if 'src_ip' in packet:
                src_ips.add(packet['src_ip'])
            if 'dst_ip' in packet:
                dst_ips.add(packet['dst_ip'])
        
        # Combine for all unique IPs
        all_ips = src_ips.union(dst_ips)
        
        return src_ips, dst_ips, all_ips
    
    except FileNotFoundError:
        print(f"Error: The file {json_file_path} was not found.")
        return set(), set(), set()
    except json.JSONDecodeError:
        print("Error: The file is not a valid JSON file.")
        return set(), set(), set()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return set(), set(), set()

def count_ip_occurrences(json_file_path):
    """
    Count occurrences of each IP address (both as source and destination)
    
    Args:
        json_file_path (str): Path to the JSON file
        
    Returns:
        Counter: Counter object with IPs and their occurrence counts
    """
    try:
        # Open and load the JSON file
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        
        if 'packets' not in data:
            return Counter()
        
        ip_counter = Counter()
        
        for packet in data['packets']:
            if 'src_ip' in packet:
                ip_counter[packet['src_ip']] += 1
            if 'dst_ip' in packet:
                ip_counter[packet['dst_ip']] += 1
        
        return ip_counter
    
    except Exception:
        return Counter()

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_json_file>")
        sys.exit(1)
    
    json_file_path = sys.argv[1]
    src_ips, dst_ips, all_ips = extract_unique_ips(json_file_path)
    
    print(f"Found {len(src_ips)} unique source IP addresses:")
    for ip in sorted(src_ips):
        print(f"  - {ip}")
    
    print(f"\nFound {len(dst_ips)} unique destination IP addresses:")
    for ip in sorted(dst_ips):
        print(f"  - {ip}")
    
    print(f"\nTotal unique IP addresses: {len(all_ips)}")
    
    # Get IP frequency counts
    ip_counts = count_ip_occurrences(json_file_path)
    if ip_counts:
        print("\nIP address frequencies (top 10):")
        for ip, count in ip_counts.most_common(10):
            print(f"  - {ip}: {count} occurrences")

if __name__ == "__main__":
    main()