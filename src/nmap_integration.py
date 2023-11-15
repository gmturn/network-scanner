import nmap

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, hosts=None, arguments=None, scan_type='basic', host_file=None):
        if host_file and hosts:
            raise ValueError("Specify either host/s or a host_file, not both.")

        if arguments:
            scan_arguments = arguments
        else:
            scan_arguments = self._get_scan_arguments(scan_type)

        if host_file:
            hosts = self._read_hosts_from_file(host_file)
            self.scanner.scan(hosts=self.format_hosts_for_nmap(hosts), arguments=scan_arguments)
            return self._format_scan_results()
        
        else:
            self.scanner.scan(hosts=hosts, arguments=scan_arguments)
            return self._format_scan_results()


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