# Network Vulnerability Scanner

## Overview

This Nmap Scanner Program is a Python-based tool that interfaces with Nmap, a powerful network scanning and host discovery tool. It is designed to facilitate network administrators and cybersecurity professionals in performing network scans, analyzing network security, and cataloging network resources.

## Features

- **Scanning**: Perform various types of network scans including basic, stealth, aggressive, and OS detection.
- **Host File Processing**: Ability to read hosts from a file for batch scanning.
- **Data Retrieval**: Fetch specific data like open ports, port states, hostnames, and service/product information.
- **JSON Output**: Scan results are formatted in JSON for easy parsing and integration with other tools.
- **Flexibility**: Customize scans with specific hosts or host files, and select different types of scans based on requirements.

## Installation

Ensure you have Python installed on your system. This program requires the `python-nmap` library.

1. Install Nmap: [Download and install Nmap](https://nmap.org/download.html) if it's not already installed on your system.
2. Clone this repository: `git clone <repository-url>`.
3. Install dependencies: Run `pip install -r requirements.txt` to install the required Python libraries.

## Usage

### Basic Usage

To perform a scan, instantiate the `NmapScanner` class and call the `scan` method:

```python
from nmap_integration import NmapScanner

scanner = NmapScanner()
scanner.scan(hosts='192.168.1.0/24', scan_type='basic')
```

### Reading Hosts from a File

To scan a list of hosts from a file:

```
scanner.scan(host_file='path/to/hostfile.txt', scan_type='stealth')
```
