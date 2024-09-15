import socket
from scapy.all import ARP, Ether, srp

# Correct network interface name
interface = 'Ethernet 3'

# Define the target IP range based on your subnet mask
target_ip = "10.91.11.0/24"  # Adjusted to match the /24 subnet range

# Create an ARP request addressed to the target IP range
arp = ARP(pdst=target_ip)
# Create an Ethernet frame to broadcast the ARP request
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# Stack the Ethernet frame and ARP request together
packet = ether / arp

print(f"Scanning network range: {target_ip} on interface: {interface}")
# Send the packet and capture the responses
result = srp(packet, iface=interface, timeout=2, verbose=True)[0]

# List to store detected devices
devices = []

# Extract IP and MAC addresses from the responses
for sent, received in result:
    ip_address = received.psrc
    mac_address = received.hwsrc
    devices.append({'ip': ip_address, 'mac': mac_address})

# Define the ports to check
scpi_ports = [8000, 8001, 8002]

# Display the detected devices that respond to SCPI commands
print("Available devices in the network:")
print("IP Address       MAC Address       Device Name")
print("---------------------------------------------")

for device in devices:
    ip = device['ip']
    mac = device['mac']
    device_name = "Unknown"

    for port in scpi_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # Set a timeout for the connection attempt
                s.connect((ip, port))  # Try each port

                # Send *REM command to set the device to remote mode
                s.sendall(b"*REM\n")
                # Send *IDN? command to query the device
                s.sendall(b"*IDN?\n")

                # Receive and decode the response
                response = s.recv(1024).decode('utf-8').strip()
                device_name = response
                break  # Exit loop if device is found and name is retrieved
        except Exception as e:
            continue  # Try the next port if current port fails

    # Only print devices that responded to SCPI commands
    if device_name != "Unknown":
        print(f"{ip:16}    {mac:17}    {device_name}")
