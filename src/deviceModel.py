class NetworkDevice:
    def __init__(self, ipAddr='none', macAddr='none'):
        self.ipAddr = ipAddr
        self.macAddr = macAddr


    def __str__(self):
        output = self.ipAddr + "\t\t" + self.macAddr
        return output
    