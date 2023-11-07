## PYScanLAN

PYScanLAN is a Python3 program designed for scanning VLANs on a Linux system, by checking all or specified VLAN tags.

### Usage

1. Configure the options in the `config.ini` file.
2. Run the program using the command `python3 PYScanLAN.py`.
3. The program will scan the specified VLANs and output the results to a JSON.

# Configuration Options

This section provides explanations for the various configuration options available in the script. Set in the config.ini file

#### `INTERFACE`

- **Description**: Set this variable to the desired network interface.
- **Example**: `INTERFACE = 'eth1'`

#### `DHCP_WAIT_TIME`

- **Description**: Specifies the wait time (in seconds) for DHCP lease acquisition.
- **Example**: `DHCP_WAIT_TIME = 15`

#### `CALCULATE_POSSIBLE_HOSTS`

- **Description**: When set to `True`, the script calculates the total possible hosts in each network based on the subnet mask.
- **Example**: `CALCULATE_POSSIBLE_HOSTS = True`

#### `CALCULATE_SUBNET_MASK`

- **Description**: When set to `True`, the script adds the regular subnet mask (e.g., "255.255.255.0") from the CIDR notation (e.g., "/24").
- **Example**: `CALCULATE_SUBNET_MASK = True`

#### `VLAN_CHECK_RANGE_START` and `VLAN_CHECK_RANGE_END`

- **Description**: Specifies the range of VLAN IDs to check.
- **Example**:
  ```python
  VLAN_CHECK_RANGE_START = 1
  VLAN_CHECK_RANGE_END = 4096

#### `LEASE_FILE_PATH`

- **Description**: Path to the DHCP client lease file. The script uses this file to obtain DHCP configuration details.
- **Example**: `LEASE_FILE_PATH = '/var/lib/dhcp/dhclient.leases'`

Ensure that this path points to the correct location of the DHCP client lease file on your system. The script relies on the information stored in this file for DHCP-related operations.

### Requirements

- Python 3.x
- Linux operating system (Preferably Debian, it was devoloped on Debian)


#### Example Output
```json
{
    "detected_networks": [
        {
            "vlan_id": "default",
            "ip_address": "100.110.152.81",
            "domain": "he.orld.fl.wtsky.net"
        },
        {
            "vlan_id": 6,
            "rx_bytes": 38725,
            "ip_address": "10.110.6.109",
            "cidr_subnet_mask": 24,
            "possible_host_count": 254,
            "subnet_mask": "255.255.255.0",
            "domain": "orld.fl.wtsky.net"
        },
        {
            "vlan_id": 10,
            "rx_bytes": 901,
            "ip_address": "10.110.10.245",
            "cidr_subnet_mask": 24,
            "possible_host_count": 254,
            "subnet_mask": "255.255.255.0"
        }
    ]
}
```