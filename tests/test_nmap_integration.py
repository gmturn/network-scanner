import sys
import os

# Add the src directory to PYTHONPATH
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Add the src directory to PYTHONPATH
sys.path.insert(0, src_dir)


from nmap_integration import NmapScanner


def test_scan_hosts():
    # Initialize the NmapScanner
    scanner = NmapScanner()

    # Define the target for scanning
    # This should be a safe target; ideally, use your own network or a test environment
    target = "192.168.1.72"
    hostfile = "C:\\Users\\mclea\\OneDrive\\Desktop\\Projects\\vulnerability-scanner\\src\\iplist.txt"

    # Perform the scan
    #result = scanner.scan(scan_type='os', host_file=hostfile)
    result = scanner.scan(scan_type='os', hosts="192.168.1.65-73")

    # Display the results
    print("Nmap Scan Results:")
    print(result)

if __name__ == "__main__":
    test_scan_hosts()
