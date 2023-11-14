import scapy.all as scapy 


class NetworkDevice:
    def __init__(self, ipAddr='none', macAddr='none'):
        self.ipAddr = ipAddr
        self.macAddr = macAddr

    def __str__(self):
        output = self.ipAddr + "\t\t" + self.macAddr
        return output


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
            device = NetworkDevice(ipAddr= element[1].psrc, macAddr=element[1].hwsrc)
            self.devices.append(device)
        
        for requestPacket in unansweredDevices:
            self.unansweredDevices.append(requestPacket.pdst)
            