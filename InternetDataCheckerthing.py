import psutil
import time
import requests

# Define the network interface you want to monitor (e.g., 'eth0' or 'wlan0')
interface = 'Wi-Fi'

def get_bytes(interface):
    # Get the current number of bytes received and transmitted on the interface
    stats = psutil.net_io_counters(pernic=True)
    if interface in stats:
        return stats[interface].bytes_recv, stats[interface].bytes_sent
    else:
        print(f"Interface {interface} not found.")
        return 0, 0

# Send some data over the network as a test
def send_test_data():
    url = "http://example.com"
    try:
        response = requests.get(url)
        print(f"Sent test request to {url}, status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending test request: {e}")

# Verify the network interface is correct
print(f"Available network interfaces: {list(psutil.net_io_counters(pernic=True).keys())}")

# Check if the specified interface is correct
if interface not in psutil.net_io_counters(pernic=True):
    print(f"Interface {interface} not found. Please check the network interface name.")
    exit(1)

# Get the initial byte counts
while True:
    rx_start, tx_start = get_bytes(interface)
    
    # Wait for a specified interval (e.g., 5 seconds)
    time.sleep(5)

    # Send test data
    send_test_data()

    # Get the byte counts after the wait
    rx_end, tx_end = get_bytes(interface)

    # Calculate data transfer during the wait period
    rx_bytes = rx_end - rx_start
    tx_bytes = tx_end - tx_start

    # Print the detected data transfer
    print(f"Data received: {rx_bytes} bytes, Data sent: {tx_bytes} bytes")

    # Convert bytes to megabytes
    truepowerything = True
    filedatathing = ""
    try:
        with open("labelnum.txt", "r") as file:
            filedatathing = file.read()
    except:
        truepowerything = False
        with open("labelnum.txt", "w") as file:
            file.write("0")
    
    if truepowerything == True:
        filedatathing2 = int(filedatathing) + 5
        filedatathing3 = ""
        try:
            with open("internetspeed.txt", "r") as file:
                filedatathing3 = file.read()
                filedatathing3 = int(filedatathing3)
                filedatathing3 += (tx_bytes + rx_bytes)
                print("FILEDATATHING3: " + str(filedatathing3))
                filedatathing3 = str(filedatathing3)
                with open("internetspeed.txt", "w") as file3:
                    file3.write(filedatathing3)
        except:
            with open("internetspeed.txt", "w") as file:
                file.write(str(tx_bytes + rx_bytes))
        
        if filedatathing2 < 86405:
            with open("labelnum.txt", "w") as file:
                file.write(str(filedatathing2))
        else:
            with open("labelnum.txt", "w") as file:
                file.write("0")
            with open("internetspeed.txt", "w") as file:
                file.write("0")
