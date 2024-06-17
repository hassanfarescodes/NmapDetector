### LIBRARIES ###
import subprocess
import random
import os
#################


####### COLORS AND SYMBOLS #######
CM = '\u2713'                 # Check Tick
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


########### CHECK NETIFACES ##########
try:
    import netifaces
    color(f"\n[{CM}] NETIFACES IS INSTALLED!", B_GREEN)
except ImportError:
    color("\n[!] PLEASE INSTALL NETIFACES MODULE FOR PYTHON!", B_RED)
    os._exit(0)
######################################


############## FUNCTIONS #############
def get_interfaces():
    """
    Returns network interfaces
    """
    return netifaces.interfaces()

def random_mac():
    """
    Generates a random MAC address
    """
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)
    )

def change_mac(interface, new_mac):
    try:
        RETRY = 5  # Number of retries to assign mac address
        subprocess.run(["sudo", "ifconfig", interface, "down"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True, stderr=subprocess.DEVNULL)
        color(f"\n[*] Changed MAC address of {interface} to {new_mac}", B_GREEN)
        
    except subprocess.CalledProcessError:
        RETRY -= 1
        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True, stderr=subprocess.DEVNULL)
        new_mac = random_mac()
        change_mac(interface, new_mac)
        if RETRY <= 0:
            color("\n[!] FAILED TO CHANGE MAC ADDRESS, RETRY TIMEOUT", B_ORANGE)
######################################


############ MAIN FUNCTION ############
if __name__ == "__main__":
    interfaces = get_interfaces()
    color("\n[-] Available network interfaces:", B_PURPLE)
    for i, inface in enumerate(interfaces):
        color(f"{i}- {inface}", WHITE)
    interface_index = int(input("\nSelect an interface: "))
    interface = interfaces[interface_index]
    new_mac = random_mac()
    change_mac(interface, new_mac)
#######################################
