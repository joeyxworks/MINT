import socket
import threading
import queue
import ipaddress
import sys
import os
import time
import struct

# The menu to select which module to run.
def main_menu():
    while True:
        print("\nNetwork Analyst Tool")
        print("1. Threaded Port Scanner")
        print("2. UDP Ping (Unthreaded)")
        print("3. ICMP Traceroute")
        print("4. Under Development")
        print("5. Under Development")
        print("0. Exit")

        try:
            choice = input("\nSelect an option: ")
            
            if choice == '1':
                threaded_port_scan_main()
            elif choice == '2':
                udp_ping_main()
            elif choice == '3':
                icmp_traceroute_main()
            elif choice in ['4', '5']:
                print("This feature is under development. Please check back later.")
            elif choice == '0':
                print("Exiting the program. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        except KeyboardInterrupt:
            print("\nExiting the program. Goodbye!")
            sys.exit(0)

######### Input Management ##########

def get_module_inputs(module_name):
    try:
        if module_name == "port_scanner":
            # Starting IP
            start_ip = input("Enter starting IP address: ").strip()
            try:
                ipaddress.IPv4Address(start_ip)
            except ipaddress.AddressValueError:
                print("Invalid IP address format.")
                return None

            # Ending IP
            end_ip = input("Enter ending IP address (leave blank to scan only starting IP): ").strip()
            if not end_ip:
                end_ip = start_ip
            else:
                try:
                    ipaddress.IPv4Address(end_ip)
                except ipaddress.AddressValueError:
                    print("Invalid IP address format.")
                    return None

            # Starting Port
            try:
                start_port = int(input("Enter starting TCP port (0 to scan all ports): ").strip())
            except ValueError:
                print("Invalid port number. Must be an integer.")
                return None

            # Ending Port
            if start_port == 0:
                port_range = range(1, 65536)
            else:
                end_port_input = input("Enter ending TCP port (leave blank to scan only starting port): ").strip()
                if not end_port_input:
                    end_port = start_port
                else:
                    try:
                        end_port = int(end_port_input)
                    except ValueError:
                        print("Invalid port number.")
                        return None
                
                # Validate port range
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print("Invalid port range.")
                    return None
                    
                port_range = range(start_port, end_port + 1)

            return start_ip, end_ip, port_range

        elif module_name == "udp_ping":
            # UDP Ping Inputs
            target_ip = input("Enter the target IP Address: ").strip()
            try:
                ipaddress.IPv4Address(target_ip)
            except ipaddress.AddressValueError:
                print("Invalid IP address format.")
                return None
                
            port_input = input("Enter the target port number (e.g., 53): ").strip()
            try:
                port = int(port_input) if port_input else 53
            except ValueError:
                print("Invalid port number.")
                return None
                
            return target_ip, port

        elif module_name == "traceroute":
            # Traceroute Input
            target_url = input("Enter target IP or Domain to trace: ").strip()
            if not target_url:
                print("Target cannot be empty.")
                return None
                
            return target_url

    except KeyboardInterrupt:
        print("\n\n[!] Input cancelled by user. Returning to menu...")
        return None

######### Threaded Port Scanner Module #########
# --- Shared state ---
results = []
results_lock = threading.Lock()

# Worker function for threads: pulls tasks from the queue and attempts TCP connection
def scan_worker(task_queue):
    """Worker thread: pulls (ip, port) tasks and attempts TCP connection."""
    while True:
        try:
            ip, port = task_queue.get_nowait()
        except queue.Empty:
            break

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    with results_lock:
                        results.append((ip, port))
        except Exception:
            pass
        finally:
            task_queue.task_done()

# To generate a list of IP addresses from start to end
def get_ip_range(start_ip, end_ip):
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    if start > end:
        raise ValueError("Starting IP must be less than or equal to ending IP.")
    return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]

# Main function to manage the threaded port scanning process
def threaded_port_scan_main():

    print("\n--- Port Scanner ---\n")

    # Collect inputs
    # inputs = prompt_inputs()
    inputs = get_module_inputs("port_scanner")
    if inputs is None:
        return

    start_ip, end_ip, port_range = inputs

    # Build IP list
    try:
        ip_list = get_ip_range(start_ip, end_ip)
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Build task queue
    task_queue = queue.Queue()
    for ip in ip_list:
        for port in port_range:
            task_queue.put((ip, port))

    total_tasks = task_queue.qsize()
    print(f"\nScanning {len(ip_list)} IP(s) across {len(port_range)} port(s) [{total_tasks} total tasks]...")

    # Clear previous results
    results.clear()

    # Spawn up to 5 worker threads
    num_threads = min(5, total_tasks)
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=scan_worker, args=(task_queue,), daemon=True)
        t.start()
        threads.append(t)

    # Wait for all threads to complete but allow Ctrl+C
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
        
    # Sort results: by IP (numerically) then by port
    results.sort(key=lambda x: (int(ipaddress.IPv4Address(x[0])), x[1]))

    # Output
    print()
    if not results:
        print("No open ports found.")
    else:
        for ip, port in results:
            print(f"IP Address: {ip}, Port {port} is open.")


####### UDP Ping Module #######

def create_payload(name_str, target_size=56):
    # create a byte array of the specified size, filled with the name string (truncated or padded as needed)
    data = name_str.encode('utf-8')
    
    if len(data) < target_size:
        data += b'\x00' * (target_size - len(data))
    elif len(data) > target_size:
        data = data[:target_size]
        
    return data

def send_single_ping(target, port, data):
    # send single UDP packet and wait for response
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    # for UDP, we just send the packet and wait for any response (like ICMP Port Unreachable)
    start_time = time.perf_counter()
    
    try:
        sock.sendto(data, (target, port))
        response, addr = sock.recvfrom(1024)
        end_time = time.perf_counter()
        
        # compute RTT in milliseconds
        rtt_ms = int((end_time - start_time) * 1000)
        return rtt_ms
        
    except (socket.timeout, ConnectionResetError):
        return None
        
    finally:
        sock.close()

def print_statistics(target, sent, received, rtt_list):
    # compute packet loss
    lost = sent - received
    loss_pct = int((lost / sent) * 100) if sent > 0 else 0
    
    print(f"\nPing statistics for {target}:")
    print(f"    Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_pct}% loss)")
    
    if received > 0:
        min_rtt = min(rtt_list)
        max_rtt = max(rtt_list)
        avg_rtt = int(sum(rtt_list) / received)
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min_rtt}ms, Maximum = {max_rtt}ms, Average = {avg_rtt}ms")

# the main function to manage the UDP ping process
def udp_ping_main():

    print("\n--- UDP Ping ---\n")

    # get user inputs
    inputs = get_module_inputs("udp_ping")
    if inputs is None:
        return
    target, port = inputs
    
    # generate payload
    data = create_payload("Jian Chen", 56)
    
    print(f"Pinging {target} with 56 bytes of data:")
    
    sent = 0
    received = 0
    rtt_list = []
    
    # send 5 pings
    for _ in range(5):
        sent += 1
        rtt_ms = send_single_ping(target, port, data)
        
        if rtt_ms is not None:
            rtt_list.append(rtt_ms)
            received += 1
            print(f"Reply from {target}: bytes=56 time={rtt_ms}ms TTL=119")
        else:
            print("Request timed out.")
            
    # print final statistics
    print_statistics(target, sent, received, rtt_list)

####### ICMP Traceroute Module #######
def calculate_checksum(data):
    # Calculate the checksum of the given data (ICMP header + payload).
    if len(data) % 2 != 0:
        data += b'\0'
    res = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff

def create_icmp_request(seq_num):
    # Build an ICMP Echo Request packet with the given sequence number. The identifier is fixed at 12345 for simplicity.
    # ICMP Type 8 is Echo Request, Code 0. 
    # struct.pack format: B (1 byte), B (1 byte), H (2 bytes), H (2 bytes), H (2 bytes)
    header = struct.pack('!BBHHH', 8, 0, 0, 12345, seq_num)
    data = b'Traceroute_Payload'
    
    # Calculate checksum on header + data, then repack the header with the real checksum
    chksum = calculate_checksum(header + data)
    header = struct.pack('!BBHHH', 8, 0, chksum, 12345, seq_num)
    
    return header + data

def trace_single_hop(target, ttl):
    # Create a raw socket to send an ICMP Echo Request with the specified TTL. Wait for a response and return the router's IP, RTT, and ICMP type.
    # IMPORTANT: SOCK_RAW requires Administrator/Root privileges!
    # socket.IPPROTO_ICMP tells the OS we are manually building an ICMP packet.
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(2.0)
    
    # This is the magic line: It forces the IP packet to use our custom TTL
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    
    packet = create_icmp_request(seq_num=ttl)
    start_time = time.perf_counter()
    
    try:
        sock.sendto(packet, (target, 1)) # Port 1 is ignored for ICMP, but required by sendto
        
        # Listen for the router's ICMP error or the target's ICMP reply
        recv_packet, addr = sock.recvfrom(1024)
        end_time = time.perf_counter()
        
        rtt_ms = int((end_time - start_time) * 1000)
        router_ip = addr[0]
        
        # Unpack the ICMP header from the received packet (starts at byte 20 of the IP packet)
        icmp_header = recv_packet[20:28]
        icmp_type, _, _, _, _ = struct.unpack('!BBHHH', icmp_header)
        
        return router_ip, rtt_ms, icmp_type
        
    except socket.timeout:
        return "*", None, None
        
    finally:
        sock.close()

# Main manager function for the traceroute.
def icmp_traceroute_main():

    print("\n--- ICMP Traceroute ---\n")

    print("Please run this program with Administrator/Root privileges to perform traceroute.\n")
    inputs = get_module_inputs("traceroute")
    if inputs is None:
        return
    target_url = inputs
    target_ip = socket.gethostbyname(target_url)
    max_hops = 30
    
    print(f"Tracing route to {target_url} [{target_ip}] over a maximum of {max_hops} hops:\n")
    
    for ttl in range(1, max_hops + 1):
        router_ip, rtt_ms, icmp_type = trace_single_hop(target_ip, ttl)
        
        # Format the output based on whether we got a timeout or a response
        if router_ip == "*":
            print(f"{ttl:2d}    * ms    Request timed out.")
        else:
            print(f"{ttl:2d}    {rtt_ms} ms    {router_ip}")
        
        # ICMP Type 0 is an "Echo Reply", which means we reached the final destination!
        if icmp_type == 0:
            print("\nTrace complete.")
            break


if __name__ == "__main__":
    main_menu()

