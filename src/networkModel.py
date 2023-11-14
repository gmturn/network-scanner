import scapy.all as scapy 
from src.deviceModel import NetworkDevice


class NetworkScanner:
    def __init__(self, ipAddr_range='192.168.1.1/24', macAddr='ff:ff:ff:ff:ff:ff', timeout=2, verbose=False): # default ip address to home network format
        self.ipAddr_range = ipAddr_range
        self.macAddr = macAddr
        self.timeout = timeout
        self.verbose = verbose
        self.devices = [] # storing device objects
        self.unansweredDevices = []

    def scanNetwork(self):
        request = scapy.ARP(pdst=self.ipAddr_range)
        broadcast = scapy.Ether(dst=self.macAddr)
        requestBroadcast = broadcast / request
        allDevices = scapy.srp(requestBroadcast, timeout=self.timeout, verbose=self.verbose)
        answeredDevices = allDevices[0]
        unansweredDevices = allDevices[1]

        for element in answeredDevices:
            device = NetworkDevice(ipAddr= element[1].psrc, macAddr=element[1].hwsrc) # getting the IP and MAC address from the tuple
            self.devices.append(device)
        
        for requestPacket in unansweredDevices: # getting the IP address from the packet
            self.unansweredDevices.append(requestPacket.pdst)

        for device in self.devices:
            print(device.ipAddr)
            