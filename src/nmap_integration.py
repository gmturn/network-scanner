import nmap
import json

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.scan_results = {}

    def scan(self, hosts=None, arguments=None, scan_type='basic', host_file=None, traceroute=False):
        if host_file and hosts:
            raise ValueError("Specify either host/s or a host_file, not both.")


        if arguments:
            scan_arguments = arguments
        else:
            scan_arguments = self._get_scan_arguments(scan_type)

        if traceroute:
            scan_arguments = scan_arguments + " --traceroute"
        

        # read from host file if one is given
        if host_file:
            hosts = self._read_hosts_from_file(host_file)
            self.scanner.scan(hosts=self.format_hosts_for_nmap(hosts), arguments=scan_arguments)
            self.scan_results = self._format_scan_results()
            return self.scan_results
        
        else:
            self.scanner.scan(hosts=hosts, arguments=scan_arguments)
            self.scan_results = self._format_scan_results()
            return self.scan_results


    def _read_hosts_from_file(self, host_file):
        hosts = []
        try:
            with open(host_file, 'r') as hostsFile:
                for line in hostsFile:
                    host = line.strip()
                    if host:
                        hosts.append(host)
        
        except FileNotFoundError:  # file not found
            raise FileNotFoundError(f"The specified host file {host_file} was not found.")
        
        except IOError as e:  # error during file reading
            raise IOError(f"An error occurred while reading {host_file}: {e}")
        return hosts

    @staticmethod
    def format_hosts_for_nmap(hosts):
        return ' '.join(hosts)

    @staticmethod
    def _get_scan_arguments(scan_type):
        scan_options = {
            'basic': '-sV',
            'stealth': '-sS',
            'aggressive': '-A',
            'os': '-O'
        }
        return scan_options.get(scan_type, '-sV')  # Default to 'basic' if scan_type is unknown
    
    def _format_scan_results(self):
        results = {}
        for host in self.scanner.all_hosts():
            host_info = {
                'state': self.scanner[host].state(),
                'hostnames': self.scanner[host].hostnames(),
                'protocols': {}
            }
            
            for protocol in self.scanner[host].all_protocols():
                host_info['protocols'][protocol] = {
                    'ports': list(self.scanner[host][protocol].keys())
                }
                for port in self.scanner[host][protocol].keys():
                    host_info['protocols'][protocol][port] = self.scanner[host][protocol][port]
            
            results[host] = host_info

        return results
    

    def get_all_scan_data(self):
        """
        Returns all data from the most recent scan.
        """
        if hasattr(self, 'scanner') and self.scanner.all_hosts():
            return self.scanner._scan_result
        else:
            return "No scan data available or scan not performed."


    # host_ips should be passed in as a list --> if host_ips == none, display all IPs stored in the scan
    def display_scan_data(self, host_ips=None, data=None):
        if host_ips and data == None:
            pass

    def get_open_ports_and_states(self, host):
        """
        Retrieves open ports and their states for a given host.
        """
        if host not in self.scanner.all_hosts():
            return {}  # or some error handling

        ports_states = {}
        for protocol in self.scanner[host].all_protocols():
            ports = self.scanner[host][protocol].keys()
            for port in ports:
                state = self.scanner[host][protocol][port]['state']
                if state == 'open':
                    ports_states[port] = state
        return ports_states

    def get_open_ports_and_services(self, host):
        """
        Retrieves open ports and the services running on them for a given host.
        """
        if host not in self.scanner.all_hosts():
            return {}  # or some error handling

        ports_services = {}
        for protocol in self.scanner[host].all_protocols():
            ports = self.scanner[host][protocol].keys()
            for port in ports:
                state = self.scanner[host][protocol][port]['state']
                if state == 'open':
                    service = self.scanner[host][protocol][port]['name']
                    ports_services[port] = service
        return ports_services

    def get_hostname(self, host):
        """
        Retrieves the hostname of a given host.
        """
        if host not in self.scanner.all_hosts():
            return None  # or some error handling

        hostnames = self.scanner[host].hostnames()
        return hostnames

    def get_os(self, host):
        """
        Retrieves the operating system information for a given host.
        """
        if host not in self.scanner.all_hosts():
            return None  # or some appropriate error handling

        os_info = []
        if 'osmatch' in self.scanner[host]:
            for os_match in self.scanner[host]['osmatch']:
                name = os_match['name']
                accuracy = os_match['accuracy']
                os_info.append(f"{name} ({accuracy}% accuracy)")
        else:
            return ['OS Information Not Available']

        return os_info

        
    def get_traceroute_results(self, host):
        """
        Retrieves the traceroute results for a given host.
        """
        if host not in self.scanner.all_hosts():
            return "Host not found or traceroute not performed."

        if 'traceroute' in self.scanner[host]:
            traceroute_info = self.scanner[host]['traceroute']
            if 'hops' in traceroute_info and traceroute_info['hops']:
                formatted_traceroute = []
                for hop in traceroute_info['hops']:
                    hop_info = f"Hop {hop['ttl']}: {hop['ipaddr']} ({hop['rtt']} ms)"
                    formatted_traceroute.append(hop_info)
                return formatted_traceroute
            else:
                return ["Traceroute completed but no hops found."]
        else:
            return ["Traceroute information not available."]


    def convert_scan_data_json(self, scan_data):
        """
        Converts scan data into JSON format.
        """
        return json.dumps(scan_data, indent=4)
