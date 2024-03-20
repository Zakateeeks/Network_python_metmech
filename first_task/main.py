from traceroute import *
import sys


def main() -> None:
    if len(sys.argv) != 2:
        print("ERROR\nUse: bash traceroute.sh (Link)")
        sys.exit()
    else:
        site_name = sys.argv[1]

    if site_name.startswith(("127", "192.168", "10", "169.254", "172.20")):
        print("Local network")
        sys.exit()

    traceroute(site_name)


if __name__ == "__main__":
    main()
