from src.networkModel import NetworkDevice, NetworkScanner
from src.nmap_integration import NmapScanner

myDevice = NetworkDevice(ipAddr="192.168.1.156", macAddr="e0:d8:c4:ef:bb:8c")

myScanner = NetworkScanner(timeout=2)
myScanner.scanNetwork()