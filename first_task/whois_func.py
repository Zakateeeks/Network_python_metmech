import socket


def query(address, whois="whois.iana.org", port=43):
    try:
        query_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        query_socket.connect((whois, port))
        result = b""

        query_socket.sendall(address.encode("utf-8") + b"\n")

        while True:
            data = query_socket.recv(4096)
            if not data:
                break
            result += data

        query_socket.close()

        return result.decode("utf-8")
    except:
        print("WHOIS ERROR")


def check_query_info(query_result, address) -> None:
    link = "whois.iana.org"
    country = ""
    net_name = ""
    origin = ""

    if "refer" in query_result:
        begin = query_result.find("refer")
        refer = (query_result[begin:]).split("\n")[0]
        link = refer.split()[1]
        query_result = query(address, link)

    for line in query_result.split("\n"):
        check_string = line.split()
        if len(check_string) != 0:
            if check_string[0] in ("Country:", "country:"):
                if len(check_string) > 1:
                    country = check_string[1]
            if check_string[0] in ("NetName:", "netname:"):
                if len(check_string) > 1:
                    net_name = check_string[1]
            if check_string[0] in ("origin:", "OriginAS:"):
                if len(check_string) > 1:
                    origin = check_string[1]

    country = "*" if country == "" else country
    net_name = "*" if net_name == "" else net_name
    if net_name == "*" and country == "*":
        print(f"Local network\n{'=' * 60}")
    else:
        print(f"Network name: {net_name}\nCountry: {country}\nAS: {origin}\n{'=' * 60}\n")
