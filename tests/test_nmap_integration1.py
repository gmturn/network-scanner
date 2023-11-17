import unittest
import os
import sys

src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Add the src directory to PYTHONPATH
sys.path.insert(0, src_dir)
from nmap_integration import NmapScanner

class TestNmapScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = NmapScanner()
        self.target = "192.168.1.66"

    def test_scan_with_valid_host(self):
        # Test scanning a valid host
        result = self.scanner.scan(hosts=self.target, scan_type='basic')
        self.assertIn(self.target, result)

    def test_scan_with_invalid_host(self):
        # Test scanning an invalid host
        result = self.scanner.scan(hosts='invalid_host', scan_type='basic')
        self.assertTrue(result == {} or result == "No scan data available or scan not performed.")


    def test_get_open_ports_and_states(self):
        # Test getting open ports and their states
        self.scanner.scan(hosts=self.target, scan_type='basic')
        result = self.scanner.get_open_ports_and_states(self.target)
        self.assertIsInstance(result, dict)

    def test_get_open_ports_and_services(self):
        # Test getting open ports and services
        self.scanner.scan(hosts=self.target, scan_type='basic')
        result = self.scanner.get_open_ports_and_services(self.target)
        self.assertIsInstance(result, dict)

    def test_get_hostname(self):
        # Test getting hostname
        self.scanner.scan(hosts=self.target, scan_type='basic')
        result = self.scanner.get_hostname(self.target)
        self.assertIsInstance(result, list)

    def test_get_os(self):
        # Test getting operating system information
        self.scanner.scan(hosts=self.target, scan_type='os')
        result = self.scanner.get_os(self.target)
        self.assertIsInstance(result, list)

    def test_get_traceroute_results(self):
        # Test getting traceroute results
        self.scanner.scan(hosts=self.target, scan_type='basic', traceroute=True)
        result = self.scanner.get_traceroute_results(self.target)
        self.assertIsInstance(result, list)

    def test_get_all_scan_data(self):
        # Test getting all scan data
        self.scanner.scan(hosts=self.target, scan_type='basic')
        result = self.scanner.get_all_scan_data()
        self.assertIsInstance(result, dict)

    def test_convert_scan_data_json(self):
        # Test converting scan data to JSON
        self.scanner.scan(hosts=self.target, scan_type='basic')
        data = self.scanner.get_all_scan_data()
        result = self.scanner.convert_scan_data_json(data)
        self.assertIsInstance(result, str)

if __name__ == '__main__':
    unittest.main()