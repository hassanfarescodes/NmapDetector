#########################################################################
#    _______  _    _            _   _  _  __ __     __ ____   _    _    #
#   |__   __|| |  | |    /\    | \ | || |/ / \ \   / // __ \ | |  | |   #
#      | |   | |__| |   /  \   |  \| || ' /   \ \_/ /| |  | || |  | |   #
#      | |   |  __  |  / /\ \  | . ` ||  <     \   / | |  | || |  | |   #
#      | |   | |  | | / ____ \ | |\  || . \     | |  | |__| || |__| |   #
#      |_|   |_|  |_|/_/    \_\|_| \_||_|\_\    |_|   \____/  \____/    #
#                                                                       #
######################################################################### 
#  This tool is great for monitoring Nmap scans and provides the source #
#  of the scan, which allows you to block out the IP!                   #
#                                                                       #
#  Please use this tool for ethical purposes and do not rely on it      #
#  100%; It works most of the time, but make sure to scan and analyze   #
#  network traffic responsibly!       __________________________________#
#                                    | Copyright (c) 2024 Hassan Fares  #
#########################################################################


#######  STANDARD LIBRARIES  #######
import time
import threading
import socket
import os
import sys
import subprocess
####################################


####### COLORS AND SYMBOLS #######
CM = '\u2713'                 # Check Tick
ST = '\u2605'                 # Star
B_PINK = '\033[95;1;40m'      # Bright Pink
B_GREEN = '\033[32;1;40m'     # Bright Green
B_RED = '\033[38;5;196;1m'    # Bright Red
B_ORANGE = '\033[38;5;208;1m' # Bright Orange
B_PURPLE = '\033[38;5;165;1m' # Bright Purple
WHITE = '\033[97m'            # White
RESET = '\033[0m'             # Reset
##################################


#### PRINT WITH COLOR FUNCTION ####
def color(text, col):
    print(col + text + RESET)
###################################


################### CHECK IF IPTABLES IS INSTALLED ################
def iptables_check():
    try:
        result = subprocess.run(['iptables', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            color(f"\n[{CM}] IPTABLES IS INSTALLED", B_GREEN)
        else:
            color(f"\n[!] IPTABLES NOT FOUND", B_RED)
    except FileNotFoundError:
        color(f"\n[!] IPTABLES NOT FOUND", B_RED)
###################################################################


########### START UP ###########
os.system("clear") # Clear Terminal
color("[*] STARTING UP...\n", WHITE)
mac_choice = input(f"\n{ST} Would you like to spoof your MAC address? (y/n): ").lower()
block_choice = input(f"\n{ST} Would you like to block any suspicious nmap scan? (y/n): ").lower()
BLOCK = False
################################


############## CHECK SCAPY LIBRARY ################
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    color(f"\n[{CM}] Scapy is installed.", B_GREEN)
except ImportError:
    color("\n[!] Scapy is not installed.", B_RED)
    color("\n[*] Install it using \"pip3 install scapy\"", B_ORANGE)
    sys.exit(0)
##################################################


########### MAC CHANGER ###########
if mac_choice in ['yes', 'ye', 'y']:
    os.system("python3 macchanger.py")
    color("\n[*] Waiting for interface...", B_PURPLE)
    time.sleep(8) # Delay to wait for interface to come back up
###################################


############ BLOCK IPS ############
if block_choice in ['yes', 'ye', 'y']:
    iptables_check()
    BLOCK = True
###################################


################ GET USER IP ADDRESS ###############
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
user_ip = s.getsockname()[0]                        
s.close()
color(f"\n[{CM}] GOT IP", B_GREEN)
####################################################


######################### DELAY ##########################
try:
    color(f"[{CM}] INITIALIZATION SUCCESS! STARTING SCANNER...", B_GREEN)
    time.sleep(3) # Delay to check first stage of initialization
except KeyboardInterrupt:
    color("\n[!] PLEASE WAIT FOR THE INITIALIZATION!", B_RED)
    sys.exit(0)
##########################################################


#######  INITILIZATION #######
os.system("clear")             # Clears the terminal
captured_ips = []              # List for future captured IPs
stop_event = threading.Event() # Thread Event to stop threads
check_ips = {}                 # Dictionary to check ip rate
packet_limit = 20              # Packet Limit Rate per Round of Time
time_round = 5                 # Sets the time per round, if exceeded, marked as suspicious
dest_ports = {}                # Destination port sent from IP dictionary
limit_ports = 35               # Number of ports reached before detecting
block_limit = 55               # Number of ports reached before blocking
block_list = []                # List of Blocked IPS
ping_list = []                 # Used to limit ping output and spam
###############################


########################## FUNCTIONS #########################
def pattern_scan():
    """
    Detects patterns for scans, great for normal scans or fast-paced scans.
    """
    while not stop_event.is_set():
        time.sleep(time_round)
        check_ips.clear()
        
def ping_limit():
    """
    Prevents Spam messages from ping output.
    """
    while not stop_event.is_set():
        time.sleep(15)
        ping_list.clear()

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . #

def port_limit_checker():
    """
    Detects IPs that scan number of ports more than the limit ports
    Blocks IPs that scan number of ports more than block_list if user authorized
    """
    while not stop_event.is_set():
        try:
            time.sleep(0.5)
            for ip, ports in dest_ports.items():
                if(len(dest_ports[ip]) > limit_ports and ip not in captured_ips):
                    color(f"[!] NMAP SCAN DETECTED! SOURCE: {ip} with these ports scanned: {ports}", B_RED)
                    color("\n[*] REASON: MULTIPLE SYN PACKETS SENT TO MULTIPLE PORTS!", B_ORANGE)
                    captured_ips.append(ip)
                if ip.endswith("(UDP)") or ip.endswith("(TCP)"):
                    block_ip = ip[:-6]
                else:
                    block_ip = ip
                if(BLOCK and len(dest_ports[ip]) > block_limit and block_ip not in block_list):
                    os.system(f"sudo iptables -A INPUT -s {block_ip} -j DROP")
                    color(f"[!] {block_ip} HAS BEEN BLOCKED", B_RED)
                    block_list.append(block_ip)
        except RuntimeError:
            print("[!] RUNTIME ERROR OCCURED, ERROR CODE: 210")

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . #

def detect_nmap(pkt):
    """
    Detects nmap scans by using nmap packet properties such as 64 <= ttl <= 128
    and SYN/ACK packet types. Also detects scans by monitoring how many 
    ports receive SYN packets consistently.
    """
    if not stop_event.is_set():
        if IP in pkt: 
            ip = str(pkt[IP].src)
            ip2 = str(pkt[IP].dst)
            attacker_ip = ip if ip != user_ip else ip2
            if not attacker_ip.endswith('.255') and attacker_ip[0:3] != "224" and not attacker_ip.endswith('.1'):  #Exclude Broadcast IP Addresses, Multicast IPs, and Router IPs
                ttl = pkt[IP].ttl
                if TCP in pkt:
                    flags = pkt[TCP].flags
                    window_size = pkt[TCP].window
                    attacker_ip = attacker_ip + " (TCP)"
                    if attacker_ip not in captured_ips:
                        if (flags == 0x02 or flags == 0x14 or flags == 0x12 or window_size == 1024):  # SYN, SYN/ACK, ACK, or Default Window Size
                            if attacker_ip in check_ips:
                                check_ips[attacker_ip] += 1
                            else:
                                check_ips[attacker_ip] = 1
                            if check_ips[attacker_ip] >= packet_limit:
                                color(f"[!] DETECTED NMAP SCAN FROM {attacker_ip}", B_RED)
                                color("\n[*] REASON: HIGH PACKET RATES FROM THE SAME IP", B_ORANGE)
                                captured_ips.append(attacker_ip)
                elif UDP in pkt:
                    udp_payload = pkt[UDP].payload
                    if len(udp_payload) in [0, 40, 72]: #UDP payload in Nmap Scans
                        attacker_ip =  attacker_ip + " (UDP)"
                        if attacker_ip in check_ips:
                            check_ips[attacker_ip] += 1
                        else:
                            check_ips[attacker_ip] = 1
                        if check_ips[attacker_ip] >= packet_limit and attacker_ip not in captured_ips:
                                color(f"[!] DETECTED NMAP SCAN FROM {attacker_ip}", B_RED)
                                color("\n[*] REASON: HIGH PACKET RATES FROM THE SAME IP", B_RED)
                                captured_ips.append(attacker_ip) 
                elif (ICMP in pkt):
                    if 64 <= ttl <= 128 and attacker_ip not in ping_list: #Default ttl for pings
                        color(f"\n[!] {attacker_ip} PINGED YOU!", B_RED)
                        ping_list.append(attacker_ip)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . #

def port_adder(pkt):
    try:
        if not stop_event.is_set():
            attacker_ip = str(pkt[IP].dst) if str(pkt[IP].dst) != user_ip else str(pkt[IP].src)
            if attacker_ip not in block_list and not attacker_ip.endswith('.255') and attacker_ip[0:3] != "224" and not attacker_ip.endswith('.1'):  #Exclude Broadcast IP Addresses, Multicast IPs, and Router IPs
                if TCP in pkt:
                    dst_port = pkt[TCP].dport
                    src_port = pkt[TCP].sport
                if UDP in pkt:
                    dst_port = pkt[UDP].dport
                    scr_port = pkt[UDP].sport
        if attacker_ip not in dest_ports: 
            dest_ports[attacker_ip] = {dst_port}
        dest_ports[attacker_ip].add(dst_port)
        dest_ports[attacker_ip].add(src_port)
    except UnboundLocalError:
        try:
            if attacker_ip not in captured_ips and pkt[IP].flags == 1 and not stop_event.is_set():
                color(f"[!] POSSIBLE FRAGMENTED PACKETS DETECTED FROM {attacker_ip}", B_RED)
                captured_ips.append(attacker_ip)
        except UnboundLocalError:
            if not stop_event.is_set():
                color("[!] UNBOUNDLOCALERROR OCCURED", B_RED)
                os._exit(1)
            else:
                color("[!] TERMINATED", B_PINK)
                os._exit(1)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . #

def start_sniffing_ports():
    """
    Starts sniffing / detecting, function is created for exceptions and threading.
    """
    try:
        sniff(filter="tcp or udp", prn=port_adder, store=0)
    except PermissionError:
        color("[!] Please Run As Root! ER: 990", B_RED)
        os._exit(1)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . #

def start_sniffing():
    """
    Starts sniffing / detecting, function is created for exceptions and threading.
    """
    try:
        sniff(filter="tcp or udp or icmp", prn=detect_nmap, store=0)
    except PermissionError:
        color("[!] Please Run As Root! ER: 991", B_RED)
        os._exit(1)
##############################################################


##################### THREADING ######################
sniff_thread = threading.Thread(target=start_sniffing)
sniff_ports_thread = threading.Thread(target=start_sniffing_ports)
limit_ports_thread = threading.Thread(target=port_limit_checker)
pattern_thread = threading.Thread(target=pattern_scan)
ping_thread = threading.Thread(target=ping_limit)
######################################################


########### MAIN FUNCTION ##########
if __name__ == "__main__":
    color("[*] EYES OUT! ᕕ(⌐■_■)ᕗ\n", WHITE)
    try:
        sniff_thread.start()
        pattern_thread.start()
        sniff_ports_thread.start()
        limit_ports_thread.start()
        ping_thread.start()
        color("[*] SCANNER STARTED...", B_PURPLE)
        sniff_thread.join()
        pattern_thread.join()
        sniff_ports_thread.join()
        limit_ports_thread.join()
        ping_thread.join()
    except KeyboardInterrupt:
        color(f"\n- CAPTURED IPS: {captured_ips}\n- BLOCKED IPS: {block_list}", WHITE)
        color("\n[!] TERMINATING...", B_PINK)
        stop_event.set()
        try:
            time.sleep(0.8)
        except KeyboardInterrupt:
            color("\n[*] STOPPED", B_PINK)
        color("\n[!] TERMINATED", B_PINK)
        os._exit(1)
###################################

#                             @@@@@@@@@@@@@                                            
#                          @@@@@@@@@@@@@@@@@@@                                            
#                      @@@@@@@@@@@@@@@@@@@@@@@@@@@                                        
#                   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                     
#                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                  
#              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                
#             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                               
#           @@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@                             
#          @@@@@@@@@        @@@@@@     @@@@@@        @@@@@@@@@                            
#         @@@@@@@@@@                                 @@@@@@@@@@                           
#        @@@@@@@@@@@                                 @@@@@@@@@@@                          
#       @@@@@@@@@@@@                                 @@@@@@@@@@@*                         
#       @@@@@@@@@@@                                   @@@@@@@@@@@                         
#      @@@@@@@@@@@                                     @@@@@@@@@@@                        
#      @@@@@@@@@@@ https://github.com/hassanfarescodes @@@@@@@@@@@                        
#      @@@@@@@@@@.                                     :@@@@@@@@@@                        
#      @@@@@@@@@@                                       @@@@@@@@@@                        
#      @@@@@@@@@@@                                     @@@@@@@@@@@                        
#      @@@@@@@@@@@                                     @@@@@@@@@@@                        
#      @@@@@@@@@@@                                     @@@@@@@@@@@                        
#      %@@@@@@@@@@@                                   @@@@@@@@@@@                         
#       @@@@@@@@@@@@                                 @@@@@@@@@@@@                         
#        @@@@@@@@@@@@@                             @@@@@@@@@@@@@                          
#        @@@@@@   @@@@@@@@                     @@@@@@@@@@@@@@@@@                          
#         @@@@@@    @@@@@@@@@@             @@@@@@@@@@@@@@@@@@@@                           
#          @@@@@@@   @@@@@@@@               @@@@@@@@@@@@@@@@@@                            
#            @@@@@@     @@@@                @@@@@@@@@@@@@@@@                              
#             @@@@@@                        @@@@@@@@@@@@@@@                               
#               @@@@@@@                     @@@@@@@@@@@@@                                 
#                 @@@@@@@@@@@               @@@@@@@@@@@                                   
#                   @@@@@@@@@               @@@@@@@@@                                     
#                      @@@@@@               @@@@@@
#                         @@@@@@@@@@@@@@@@@@@@@
#                            @@@@@@@@@@@@@@@
