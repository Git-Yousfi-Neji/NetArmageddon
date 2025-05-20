from .output_manager import CYAN, GREEN, MAGENTA, RED, RESET, YELLOW


# for feauture banners styles refer to https://manytools.org/hacker-tools/ascii-banner/
def get_dhcp_banner():
    return f"""{GREEN}     ██████╗ ██╗  ██╗ ██████╗██████╗
     ██╔══██╗██║  ██║██╔════╝██╔══██╗
     ██║  ██║███████║██║     ██████╔╝
     ██║  ██║██╔══██║██║     ██╔═══╝
     ██████╔╝██║  ██║╚██████╗██║
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝
     Flooding network with malicious DHCP requests{RESET}"""


def get_arp_banner():
    return f"""     {CYAN} █████╗ ██████╗ ██████╗
     ██╔══██╗██╔══██╗██╔══██╗
     ███████║██████╔╝██████╔╝
     ██╔══██║██╔══██╗██╔═══╝
     ██║  ██║██║  ██║██║
     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
     Maintaining phantom devices in network tables{RESET}"""


def get_traffic_banner():
    return f"""{YELLOW}   ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗
   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝
      ██║   ██████╔╝███████║█████╗  █████╗  ██║██║
      ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║
      ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗
      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝
    Capturing all passing network packets{RESET}"""


def get_deauth_banner():
    return f"""{RED}     ██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
     ██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
     ██║  ██║█████╗  ███████║██║   ██║   ██║   ███████║
     ██║  ██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
     ██████╔╝███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
     ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝{RESET}
{RED}     Disrupting wireless client connections
     Perform a Wi-Fi deauthentication attack.
     NOTE: {CYAN}you must use this tool on a wireless interface that supports
           monitor mode{RESET}{RESET}"""


def get_general_banner():
    return f"""{MAGENTA}    ▄▄▄       ██▀███   ███▄ ▄███▓ ▄▄▄        ▄████ ▓█████ ▓█████▄ ▓█████▄  ▒█████   ███▄    █
    ▒████▄    ▓██ ▒ ██▒▓██▒▀█▀ ██▒▒████▄     ██▒ ▀█▒▓█   ▀ ▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒ ██ ▀█   █
    ▒██  ▀█▄  ▓██ ░▄█ ▒▓██    ▓██░▒██  ▀█▄  ▒██░▄▄▄░▒███   ░██   █▌░██   █▌▒██░  ██▒▓██  ▀█ ██▒
    ░██▄▄▄▄██ ▒██▀▀█▄  ▒██    ▒██ ░██▄▄▄▄██ ░▓█  ██▓▒▓█  ▄ ░▓█▄   ▌░▓█▄   ▌▒██   ██░▓██▒  ▐▌██▒
    ▓█   ▓██▒░██▓ ▒██▒▒██▒   ░██▒ ▓█   ▓██▒░▒▓███▀▒░▒████▒░▒████▓ ░▒████▓ ░ ████▓▒░▒██░   ▓██░
    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ░  ░ ▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░ ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒
    ▒   ▒▒ ░  ░▒ ░ ▒░░  ░      ░  ▒   ▒▒ ░  ░   ░  ░ ░  ░ ░ ▒  ▒  ░ ▒  ▒   ░ ▒ ▒░ ░ ░░   ░ ▒░
    ░   ▒     ░░   ░ ░      ░     ░   ▒   ░ ░   ░    ░    ░ ░  ░  ░ ░  ░ ░ ░ ░ ▒     ░   ░ ░
        ░  ░   ░            ░         ░  ░      ░    ░  ░   ░       ░        ░ ░           ░ {RESET}
                        Network Stress Testing Framework
              {RED}Use with caution and only on authorized networks!{RESET}{RESET}"""
