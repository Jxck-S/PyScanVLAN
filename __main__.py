import subprocess
import json
import re
import time
import colorama
from datetime import datetime
colorama.init()
import configparser

# Read the configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')
# Access configuration parameters from the Settings section
INTERFACE = config.get('Settings', 'INTERFACE')
DHCP_WAIT_TIME = config.getint('Settings', 'DHCP_WAIT_TIME')
CALCULATE_POSSIBLE_HOSTS = config.getboolean('Settings', 'CALCULATE_POSSIBLE_HOSTS')
CALCULATE_SUBNET_MASK = config.getboolean('Settings', 'CALCULATE_SUBNET_MASK')
VLAN_CHECK_RANGE_START = config.getint('Settings', 'VLAN_CHECK_RANGE_START')
VLAN_CHECK_RANGE_END = config.getint('Settings', 'VLAN_CHECK_RANGE_END')
LEASE_FILE_PATH = config.get('Settings', 'LEASE_FILE_PATH')
# Print the configuration parameters (for verification)
print(f"INTERFACE: {INTERFACE}")
print(f"DHCP_WAIT_TIME: {DHCP_WAIT_TIME}")
print(f"CALCULATE_POSSIBLE_HOSTS: {CALCULATE_POSSIBLE_HOSTS}")
print(f"CALCULATE_SUBNET_MASK: {CALCULATE_SUBNET_MASK}")
print(f"VLAN_CHECK_RANGE_START: {VLAN_CHECK_RANGE_START}")
print(f"VLAN_CHECK_RANGE_END: {VLAN_CHECK_RANGE_END}")
print(f"LEASE_FILE_PATH: {LEASE_FILE_PATH}")

def run_command(cmd):
    """Execute a system command and return its output."""
    print(f"Running command: {cmd}")
    result = subprocess.run(cmd, capture_output=True, shell=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {result.stderr}")
    return result.stdout

def get_interface_rx_bytes(interface_name):
    try:
        # Run the ip command and capture its output
        cmd = f"ip -s link show {interface_name}"
        result = subprocess.run(cmd, capture_output=True, shell=True, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            # Extract RX bytes using regular expression
            rx_bytes_pattern = r"RX: bytes  packets  errors  dropped missed  mcast\s+(\d+)"
            match = re.search(rx_bytes_pattern, result.stdout)
            
            if match:
                # Extract and return the RX bytes value
                rx_bytes = int(match.group(1))
                return rx_bytes
            else:
                raise ValueError
        else:
            return f"Error running command: {result.stderr}"
    except Exception as e:
        return f"Error: {e}"

def extract_ip_from_interface(interface_vlan):
    """Extract the IP address from the given interface using the 'ip' command."""
    ip_output = run_command(f"ip addr show {interface_vlan}")
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_output)
    if match:
        ip_addr = match.group(1)
        # Ignore IPs starting with 169.
        if not ip_addr.startswith("169."):
            return ip_addr
    return None

def get_interface_subnet(interface_name):
    """Get the number after the / in the IP address for the specified interface."""
    cmd = f"ip addr show {interface_name}"
    output = run_command(cmd)
    subnet_pattern = r'inet \d+\.\d+\.\d+\.\d+/(\d+)'
    match = re.search(subnet_pattern, output)
    if match:
        subnet_number = match.group(1)
        return int(subnet_number)
    else:
        print(f"No IP address found for interface {interface_name}")
        return None

def cidr_to_subnet_mask(cidr_prefix):
    """
    Convert CIDR prefix to subnet mask.
    """
    subnet_mask = (1 << 32) - (1 << (32 - int(cidr_prefix)))
    # Convert subnet mask to dotted decimal format
    subnet_mask = (subnet_mask & 0xFFFFFFFF).to_bytes(4, byteorder='big')
    subnet_mask = '.'.join(map(str, subnet_mask))
    return subnet_mask

def calculate_hosts(cidr_prefix):
    """
    Calculate the number of possible hosts from CIDR notation.
    """
    num_hosts = 2 ** (32 - int(cidr_prefix)) - 2
    return num_hosts



def get_domain_name(interface_name, lease_file_path):
    try:
        with open(lease_file_path, 'r') as lease_file:
            leases = lease_file.read().split('}\n')
            for lease in leases:
                if f'interface "{interface_name}"' in lease and 'option domain-name' in lease:
                    lines = lease.split('\n')
                    for line in lines:
                        if 'option domain-name' in line:
                            parts = line.split('"')
                            if len(parts) >= 2:
                                domain_name = parts[1].strip()
                                return domain_name
    except FileNotFoundError:
        print(f"Error: Lease file not found at {lease_file_path} for interface {interface_name}")
    return None
    
def check_vlan(vlan_id):
    """Check if a VLAN interface has an IP."""
    interface_vlan = f"{INTERFACE}.{vlan_id}"
    print(f"\nChecking VLAN {vlan_id}...")

    # Create the VLAN interface using the 'ip' command
    run_command(f"ip link add link {INTERFACE} name {interface_vlan} type vlan id {vlan_id}")
    run_command(f"ip link set up {interface_vlan}")

    # Wait for 30 seconds to allow IP assignment
    print(f"Waiting for {DHCP_WAIT_TIME} Seconds")
    time.sleep(DHCP_WAIT_TIME)
    vlan_info = {'vlan_id': vlan_id}

    #Check for RX on interface
    rx_bytes = get_interface_rx_bytes(interface_vlan)
    if rx_bytes:
        print(colorama.Fore.GREEN + f"RX detected on {interface_vlan}: {rx_bytes}")
        vlan_info['rx_bytes'] = rx_bytes
    else:
        print(f"NO RX detected on {interface_vlan}: {rx_bytes}")

    # Extract IP from the interface
    ip_address = extract_ip_from_interface(interface_vlan)
    if ip_address:
        vlan_info['ip_address'] = ip_address
        print(f"VLAN {vlan_id} has IP: {ip_address}")
        cidr_mask = get_interface_subnet(interface_vlan)
        if cidr_mask:
            print(f"Has CIDR subnet mask of: /{cidr_mask}")
            vlan_info['cidr_subnet_mask'] = cidr_mask
            if CALCULATE_POSSIBLE_HOSTS:
                possible_host_count = calculate_hosts(cidr_mask)
                print(f"Possible hosts: {possible_host_count}")
                vlan_info['possible_host_count'] = possible_host_count
            if CALCULATE_SUBNET_MASK:
                subnet_mask = cidr_to_subnet_mask(cidr_mask) 
                print(f"Subnet Mask is : {subnet_mask}")
                vlan_info['subnet_mask'] = subnet_mask

        dns_domain = get_domain_name(interface_vlan, LEASE_FILE_PATH)
        if dns_domain:
            print(f"DNS Domain: {dns_domain}")
            vlan_info['domain'] = dns_domain
        run_command(f"ip link delete {interface_vlan}")
    else:
        print("NO IP")
    print(colorama.Style.RESET_ALL, end="")
    if len(vlan_info) <= 1:
        print(f"VLAN {vlan_id} not detected")
        run_command(f"ip link delete {interface_vlan}")
        return None
    else:
        return vlan_info
    
def log_vlans(vlans):
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"vlan_ips_{current_datetime}.json"
    print(f"\nLogging VLANs with IPs to {log_file}...")
    with open(log_file, "w") as f:
        json.dump({"detected_networks": vlans}, f, indent=4)

def main():
    vlans_with_ips = []
    try:
        print(f"Starting checks on interface: {INTERFACE}")
        default_vlan_ip = extract_ip_from_interface(INTERFACE)
        if default_vlan_ip:
            default = {"vlan_id": "default", "ip_address": default_vlan_ip}
            print(f"default vlan ip is {default_vlan_ip}")
            dns_domain = get_domain_name(INTERFACE, LEASE_FILE_PATH)
            if dns_domain:
                print(f"DNS Domain: {dns_domain}")
                default['domain'] = dns_domain
                
            vlans_with_ips.append(default)
        # Check VLANs one by one
        for vlan_id in range(VLAN_CHECK_RANGE_START, VLAN_CHECK_RANGE_END):
            result = check_vlan(vlan_id)
            if result:
                vlans_with_ips.append(result)
    except KeyboardInterrupt:
        log_vlans(vlans_with_ips)
        print("Exited, by keyboard command")
        exit()
    # Log VLANs with IPs in JSON format
    log_vlans(vlans_with_ips)


    print("Finished checking all VLANs.")

if __name__ == "__main__":
    main()
