import sys
import time

from whois_func import *


def traceroute(site_name, timeout=1, max_hops=40, port=33434) -> None:
    try:
        dest_addr = socket.gethostbyname(site_name)
    except:
        print("Address error")
        sys.exit()

    icmp = socket.getprotobyname("icmp")
    udp = socket.getprotobyname('udp')
    old_add = 1
    ttl = 1

    while True:
        start_time = time.time()
        get_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        get_socket.settimeout(timeout)

        get_socket.bind(("", port))
        send_socket.sendto(b"", (site_name, port))

        try:
            _, curr_addr = get_socket.recvfrom(512)
            curr_addr = curr_addr[0]

            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr

        except socket.error:
            pass

        finally:
            send_socket.close()
            get_socket.close()

        if curr_addr is not None:
            curr_host = f"{curr_name}({curr_addr})" if curr_addr != curr_name else curr_addr
        else:
            curr_host = "*"
        end_time = time.time()
        if (curr_addr != old_add):
            print(f"{ttl}\t{curr_host}\t{(end_time - start_time) * 1000}\n")
            check_query_info(query(curr_addr), curr_addr)

        old_add = curr_addr

        ttl += 1
        if curr_addr == dest_addr or ttl == max_hops:
            break
