import socket
import threading
import queue
import ipaddress
import sys
import os
import time
import struct

def main_menu():
    while True:
        print("Network Analyst Tool")
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
    # 【核心技巧】把所有的逻辑都包在一个巨大的 try 里面
    try:
        if module_name == "port_scanner":
            # 里面只需要处理逻辑错误（ValueError等），不再写 KeyboardInterrupt
            start_ip = input("Enter starting IP address: ").strip()
            try:
                ipaddress.IPv4Address(start_ip)
            except ipaddress.AddressValueError:
                print("Invalid IP address format.")
                return None
                
            # ... 后续其他 input 照常写 ...
            
        elif module_name == "udp_ping":
            # ...
            pass
            
    except KeyboardInterrupt:
        # 无论在上面几百行代码的哪一个 input() 处按下 Ctrl+C，
        # 都会像坐滑梯一样，直接滑到这里统一处理！
        print("\n\n[!] Input cancelled by user. Returning to menu...")
        return None

def get_module_inputs(module_name):
    try:
        if module_name == "port_scanner":
            # --- 1. Starting IP ---
            try:
                start_ip = input("Enter starting IP address: ").strip()
                ipaddress.IPv4Address(start_ip)
            except ipaddress.AddressValueError:
                print("Invalid IP address format.")
                return None
            except KeyboardInterrupt:
                print("\nInput cancelled by user. Returning to menu...")
                return None

            # --- 2. Ending IP ---
            try:
                end_ip = input("Enter ending IP address (leave blank to scan only starting IP): ").strip()
            except KeyboardInterrupt:
                print("\nInput cancelled by user. Returning to menu...")
                return None

            if not end_ip:
                end_ip = start_ip
            else:
                try:
                    ipaddress.IPv4Address(end_ip)
                except ipaddress.AddressValueError:
                    print("Invalid IP address format.")
                    return None
                except KeyboardInterrupt:
                    print("\nInput cancelled by user. Returning to menu...")
                    return None

            # --- 3. Starting Port ---
            try:
                start_port = int(input("Enter starting TCP port (0 to scan all ports): ").strip())
            except ValueError:
                print("Invalid port number. Must be an integer.")
                return None
            except KeyboardInterrupt:
                print("\nInput cancelled by user. Returning to menu...")
                return None

            # --- 4. Ending Port (条件分支) ---
            if start_port == 0:
                port_range = range(1, 65536)
            else:
                try:
                    end_port_input = input("Enter ending TCP port (leave blank to scan only starting port): ").strip()
                except KeyboardInterrupt:
                    print("\nInput cancelled by user. Returning to menu...")
                    return None

                if not end_port_input:
                    end_port = start_port
                else:
                    try:
                        end_port = int(end_port_input)
                    except ValueError:
                        print("Invalid port number.")
                        return None
                    except KeyboardInterrupt:
                        print("\nInput cancelled by user. Returning to menu...")
                        return None
                
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print("Invalid port range.")
                    return None
                port_range = range(start_port, end_port + 1)

            return start_ip, end_ip, port_range

        elif module_name == "udp_ping":
            try:
                target_ip = input("Enter the target IP Address: ").strip()
                ipaddress.IPv4Address(target_ip)
            except ipaddress.AddressValueError:
                print("Invalid IP address format.")
                return None
            except KeyboardInterrupt:
                print("\nInput cancelled by user. Returning to menu...")
                return None
                
            try:
                port_input = input("Enter the target port number (e.g., 53): ").strip()
                port = int(port_input) if port_input else 53
            except ValueError:
                print("Invalid port number.")
                return None
            except KeyboardInterrupt:
                print("\nInput cancelled by user. Returning to menu...")
                return None
                
            return target_ip, port

        elif module_name == "traceroute":
            try:
                target_url = input("Enter target IP or Domain to trace: ").strip()
            except KeyboardInterrupt:
                print("\nInput cancelled by user. Returning to menu...")
                return None
            
            if not target_url:
                print("Target cannot be empty.")
                return None
            return target_url

    except KeyboardInterrupt:
        # 统一在这里捕获所有输入阶段的 Ctrl+C
        print("\n\n[!] Input cancelled by user. Returning to menu...")
        return None



######### Threaded Port Scanner Module #########
# --- Shared state ---
results = []
results_lock = threading.Lock()

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

def get_ip_range(start_ip, end_ip):
    """Returns a list of IP address strings between start_ip and end_ip (inclusive)."""
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    if start > end:
        raise ValueError("Starting IP must be less than or equal to ending IP.")
    return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]


# def prompt_inputs():
#     """Collects all scan parameters from the user and returns them."""

#     # --- Starting IP ---
#     start_ip = input("Enter starting IP address: ").strip()
#     try:
#         ipaddress.IPv4Address(start_ip)
#     except ipaddress.AddressValueError:
#         print("Invalid starting IP address.")
#         return None

#     # --- Ending IP ---
#     end_ip = input("Enter ending IP address (leave blank to scan only starting IP): ").strip()
#     if not end_ip:
#         end_ip = start_ip
#     else:
#         try:
#             ipaddress.IPv4Address(end_ip)
#         except ipaddress.AddressValueError:
#             print("Invalid ending IP address.")
#             return None

#     # --- Starting Port ---
#     start_port_input = input("Enter starting TCP port (0 to scan all ports): ").strip()
#     try:
#         start_port = int(start_port_input)
#     except ValueError:
#         print("Invalid port number.")
#         return None

#     # --- Ending Port ---
#     if start_port == 0:
#         # Scan all ports
#         port_range = range(1, 65536)
#     else:
#         end_port_input = input("Enter ending TCP port (leave blank to scan only starting port): ").strip()
#         if not end_port_input:
#             end_port = start_port
#         else:
#             try:
#                 end_port = int(end_port_input)
#             except ValueError:
#                 print("Invalid ending port number.")
#                 return None

#         if start_port < 1 or end_port > 65535 or start_port > end_port:
#             print("Invalid port range.")
#             return None

#         port_range = range(start_port, end_port + 1)

#     return start_ip, end_ip, port_range


def threaded_port_scan_main():
    """Main entry point for the port scanner module."""

    print("\n--- Port Scanner ---")

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

    # Wait for all threads to complete
    # for t in threads:
    #     t.join()

    # # Sort results: by IP (numerically) then by port
    # results.sort(key=lambda x: (int(ipaddress.IPv4Address(x[0])), x[1]))

    # Wait for all threads to complete but allow Ctrl+C
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.1) # 主线程短暂休眠，随时准备响应 KeyboardInterrupt
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0) # 直接干净利落地退出程序
        
    # Sort results: by IP (numerically) then by port
    results.sort(key=lambda x: (int(ipaddress.IPv4Address(x[0])), x[1]))

    # Output
    print()
    if not results:
        print("No open ports found.")
    else:
        for ip, port in results:
            print(f"IP Address: {ip}, Port {port} is open\n\n")


####### UDP Ping Module #######
# def get_user_inputs():
#     """获取用户输入的 IP 地址和端口"""
#     target = input("Enter the starting IP Address to scan: ")
#     port_input = input("Enter the target port number (e.g., 53): ")
#     port = int(port_input) if port_input else 53
#     return target, port

def create_payload(name_str, target_size=56):
    """生成指定大小的数据包负载（包含你的名字）"""
    data = name_str.encode('utf-8')
    
    if len(data) < target_size:
        data += b'\x00' * (target_size - len(data))
    elif len(data) > target_size:
        data = data[:target_size]
        
    return data

def send_single_ping(target, port, data):
    """发送单个 UDP ping 并返回 RTT（如果超时则返回 None）"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    start_time = time.perf_counter()
    
    try:
        sock.sendto(data, (target, port))
        response, addr = sock.recvfrom(1024)
        end_time = time.perf_counter()
        
        # 计算 RTT (毫秒)
        rtt_ms = int((end_time - start_time) * 1000)
        return rtt_ms
        
    except (socket.timeout, ConnectionResetError):
        return None
        
    finally:
        sock.close()

def print_statistics(target, sent, received, rtt_list):
    """计算并打印最终的统计数据"""
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

def udp_ping_main():
    """主函数：负责统筹和调用其他所有函数"""
    # 1. 获取输入
    # target, port = get_user_inputs()
    target, port = get_module_inputs("udp_ping")
    
    # 2. 生成 56 bytes 的数据
    data = create_payload("Jian Chen", 56)
    
    print(f"Pinging {target} with 56 bytes of data:")
    
    sent = 0
    received = 0
    rtt_list = []
    
    # 3. 循环发送 5 次
    for _ in range(5):
        sent += 1
        rtt_ms = send_single_ping(target, port, data)
        
        if rtt_ms is not None:
            rtt_list.append(rtt_ms)
            received += 1
            print(f"Reply from {target}: bytes=56 time={rtt_ms}ms TTL=119")
        else:
            print("Request timed out.")
            
    # 4. 打印统计结果
    print_statistics(target, sent, received, rtt_list)

####### ICMP Traceroute Module #######
def calculate_checksum(data):
    """Calculates the necessary checksum for the ICMP header."""
    if len(data) % 2 != 0:
        data += b'\0'
    res = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff

def create_icmp_request(seq_num):
    """Builds a raw ICMP Echo Request packet."""
    # ICMP Type 8 is Echo Request, Code 0. 
    # struct.pack format: B (1 byte), B (1 byte), H (2 bytes), H (2 bytes), H (2 bytes)
    header = struct.pack('!BBHHH', 8, 0, 0, 12345, seq_num)
    data = b'Traceroute_Payload'
    
    # Calculate checksum on header + data, then repack the header with the real checksum
    chksum = calculate_checksum(header + data)
    header = struct.pack('!BBHHH', 8, 0, chksum, 12345, seq_num)
    
    return header + data

def trace_single_hop(target, ttl):
    """Sends an ICMP packet with a specific TTL and waits for the router's reply."""
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

def icmp_traceroute_main():
    """Main manager function for the traceroute."""
    print("\nPlease run this program with Administrator/Root privileges to perform traceroute.\n")
    # target_url = input("Enter target IP or Domain to trace: ")
    target_url = get_module_inputs("traceroute")
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
    # if os.geteuid() != 0:
    #     print("This program must be run as root to perform certain operations.")
    #     sys.exit(1)
    main_menu()

