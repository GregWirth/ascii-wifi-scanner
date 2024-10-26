#!/usr/bin/env python3
"""
WiFi Analyzer Script

This script scans for available WiFi networks using the system's wireless interface,
parses the scan results, displays network information including signal strength,
and logs the results to a CSV file.

Usage:
    python wifi_analyzer.py [options]

Options:
    -i, --interface     Specify the wireless interface to use
    -o, --output        Specify output CSV file name
    --show-hidden       Include hidden networks in the scan
    -v, --verbose       Enable verbose output (debug mode)
"""

import subprocess
import re
import sys
import argparse
import logging
import csv
import shutil
import os

# Try to import termcolor and colorama
try:
    from termcolor import colored
except ImportError:
    print("The 'termcolor' package is not installed. Please install it using 'pip install termcolor'.")
    sys.exit(1)

try:
    from colorama import init
except ImportError:
    print("The 'colorama' package is not installed. Please install it using 'pip install colorama'.")
    sys.exit(1)

# Initialize colorama
init()


def setup_logging(verbosity):
    """
    Sets up logging based on the verbosity level.

    Parameters:
        verbosity (bool): If True, sets logging level to DEBUG.
    """
    level = logging.DEBUG if verbosity else logging.INFO
    logging.basicConfig(format='%(levelname)s: %(message)s', level=level)


def check_command_availability(command):
    """
    Checks if a command is available on the system.

    Parameters:
        command (str): The command to check.

    Exits the program if the command is not found.
    """
    if shutil.which(command) is None:
        logging.error(f"Required command '{command}' not found. Please install it and try again.")
        sys.exit(1)


def detect_wifi_interface(interface=None):
    """
    Detects the active WiFi interface using 'iw' or uses the provided one.

    Parameters:
        interface (str): The interface provided by the user.

    Returns:
        str: The detected or provided WiFi interface.

    Exits the program if no interface is detected.
    """
    if interface:
        logging.debug(f"Using provided interface: {interface}")
        return interface
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
        interfaces = re.findall(r'Interface\s+(\w+)', result.stdout)
        if interfaces:
            detected_interface = interfaces[0]
            logging.debug(f"Detected WiFi interface: {detected_interface}")
            return detected_interface
        else:
            logging.error("No WiFi interface detected.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running 'iw dev': {e.stderr}")
        sys.exit(1)


def scan_wifi(interface):
    """
    Scans WiFi networks using the detected interface and returns raw output.

    Parameters:
        interface (str): The WiFi interface to use for scanning.

    Returns:
        str: The raw output from the 'iw' scan command.

    Exits the program if scanning fails.
    """
    logging.info(f"Scanning for WiFi networks on interface '{interface}'...")
    try:
        result = subprocess.run(['iw', 'dev', interface, 'scan'], capture_output=True, text=True, check=True)
        logging.debug("WiFi scan completed.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning WiFi networks: {e.stderr}")
        sys.exit(1)


def parse_wifi_scan(scan_output, show_hidden=True):
    """
    Parses the scan output from 'iw' to extract network details.

    Parameters:
        scan_output (str): The raw output from 'iw' scan command.
        show_hidden (bool): Include hidden networks if True.

    Returns:
        list: A list of dictionaries containing network information.
    """
    networks = []
    blocks = scan_output.split('BSS ')
    for block in blocks[1:]:
        network = {}
        lines = block.strip().splitlines()
        bss_line = lines[0]
        bssid = bss_line.split('(')[0].strip()
        network['bssid'] = bssid
        for line in lines[1:]:
            line = line.strip()
            if line.startswith('freq:'):
                freq = int(line.split(':')[1].strip())
                network['frequency'] = freq / 1000  # MHz to GHz
                network['band'] = "2.4 GHz" if freq < 3000 else "5 GHz"
            elif line.startswith('SSID:'):
                ssid = line.split(':', 1)[1].strip()
                network['ssid'] = ssid if ssid else "[Hidden Network]"
            elif line.startswith('signal:'):
                signal = float(line.split(':')[1].strip().split()[0])
                network['signal'] = int(signal)
            elif line.startswith('RSN:') or line.startswith('WPA:'):
                network['encryption'] = 'on'
                if 'RSN:' in line:
                    network['wpa'] = 'WPA2'
                else:
                    network['wpa'] = 'WPA'
            elif line.startswith('capability:'):
                if 'Privacy' in line:
                    network['encryption'] = 'on'
                else:
                    network['encryption'] = 'off'
        if network.get('ssid') or show_hidden:
            networks.append(network)
    return networks


def frequency_to_channel(freq):
    """
    Converts frequency in GHz to WiFi channel number.

    Parameters:
        freq (float): The frequency in GHz.

    Returns:
        int or str: The WiFi channel number or 'N/A' if unknown.
    """
    freq_mhz = int(float(freq) * 1000)
    if 2412 <= freq_mhz <= 2472:
        channel = (freq_mhz - 2407) // 5
    elif freq_mhz == 2484:
        channel = 14
    elif 5180 <= freq_mhz <= 5825:
        channel = (freq_mhz - 5000) // 5
    else:
        channel = 'N/A'
    return channel


def signal_color(signal_level):
    """
    Returns a colorized string based on signal strength.

    Parameters:
        signal_level (int): Signal strength in dBm.

    Returns:
        str: Colorized signal strength string.
    """
    if signal_level >= -50:
        return colored(f"{signal_level} dBm", "green")
    elif signal_level >= -60:
        return colored(f"{signal_level} dBm", "yellow")
    elif signal_level >= -70:
        return colored(f"{signal_level} dBm", "magenta")
    else:
        return colored(f"{signal_level} dBm", "red")


def signal_bar_graph(signal_level):
    """
    Returns a colored bar based on signal strength.

    Parameters:
        signal_level (int): Signal strength in dBm.

    Returns:
        str: A string representing the signal strength bar.
    """
    bars = int((100 + signal_level) / 10)
    bar_str = '█' * bars
    if signal_level >= -50:
        return colored(bar_str, "green")
    elif signal_level >= -60:
        return colored(bar_str, "yellow")
    elif signal_level >= -70:
        return colored(bar_str, "magenta")
    else:
        return colored(bar_str, "red")


def fancy_header(title):
    """
    Returns a fancy header for sections.

    Parameters:
        title (str): The title to display.

    Returns:
        str: Formatted header string.
    """
    return colored(f"\n{'=' * 80}\n{title.center(80)}\n{'=' * 80}\n", "cyan", attrs=["bold"])


def format_network_info(net):
    """
    Formats network information for display.

    Parameters:
        net (dict): A dictionary containing network information.

    Returns:
        tuple: Formatted strings for SSID, signal, channel, frequency, band, encryption, wpa.
    """
    ssid = colored(net.get('ssid', '[Unknown]'), 'cyan', attrs=['bold'])
    signal = signal_color(net.get('signal', -100))
    frequency = net.get('frequency', 'N/A')
    band = net.get('band', 'N/A')
    encryption = net.get('encryption', 'off')
    wpa = net.get('wpa', 'None')
    # Calculate channel if frequency is known
    channel = frequency_to_channel(frequency) if frequency != 'N/A' else 'N/A'
    channel = colored(channel, 'yellow', attrs=['bold'])
    return ssid, signal, channel, frequency, band, encryption, wpa


def display_networks(sorted_networks):
    """
    Displays networks sorted by signal strength.

    Parameters:
        sorted_networks (list): List of networks sorted by signal strength.
    """
    print(fancy_header("WiFi Networks"))
    for net in sorted_networks:
        ssid, signal, channel, freq, band, encryption, wpa = format_network_info(net)
        print(f"Channel {channel}: {ssid} ({signal}, {freq} GHz, {band}, Encryption: {encryption}, WPA: {wpa})\n")
    print("=" * 80)


def display_signal_strength_graph(sorted_networks):
    """
    Displays a signal strength graph.

    Parameters:
        sorted_networks (list): List of networks sorted by signal strength.
    """
    print(fancy_header("WiFi Signal Strength Graph"))
    for net in sorted_networks:
        ssid, signal, channel, freq, band, encryption, wpa = format_network_info(net)
        signal_bar = signal_bar_graph(net.get('signal', -100))
        print(f"Channel {channel}: {signal_bar} {ssid} ({signal}, {freq} GHz, {band}, Encryption: {encryption}, WPA: {wpa})\n")
    print("=" * 80)


def log_to_csv(networks, filename):
    """
    Logs the scan results to a CSV file.

    Parameters:
        networks (list): List of networks to log.
        filename (str): The CSV file to write to.
    """
    try:
        with open(filename, mode='w', newline='') as file:
            fieldnames = ["Channel", "SSID", "Signal Strength", "Frequency (GHz)", "Band", "Encryption", "WPA"]
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for net in networks:
                frequency = net.get('frequency', 'N/A')
                channel = frequency_to_channel(frequency) if frequency != 'N/A' else 'N/A'
                writer.writerow({
                    "Channel": channel,
                    "SSID": net.get('ssid', '[Unknown]'),
                    "Signal Strength": net.get('signal', 'N/A'),
                    "Frequency (GHz)": frequency,
                    "Band": net.get('band', 'N/A'),
                    "Encryption": net.get('encryption', 'off'),
                    "WPA": net.get('wpa', 'None')
                })
        logging.info(f"Results logged to {filename}")
    except IOError as e:
        logging.error(f"Failed to write to file {filename}: {e}")


def parse_arguments():
    """
    Parses command-line arguments.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="WiFi Analyzer Script")
    parser.add_argument('-i', '--interface', help='Specify the wireless interface to use')
    parser.add_argument('-o', '--output', default='wifi_scan.csv', help='Specify output CSV file name')
    parser.add_argument('--show-hidden', action='store_true', help='Include hidden networks in the scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug mode)')
    return parser.parse_args()


def main():
    """
    The main function that orchestrates the WiFi scanning and output.
    """
    args = parse_arguments()
    setup_logging(args.verbose)

    # Check if script is run as root
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run it with 'sudo'.")
        sys.exit(1)

    # Check if required commands are available
    check_command_availability('iw')

    interface = detect_wifi_interface(args.interface)
    logging.info(f"Using WiFi interface: {interface}")
    wifi_scan_output = scan_wifi(interface)
    networks = parse_wifi_scan(wifi_scan_output, show_hidden=args.show_hidden)
    if not networks:
        logging.warning("No networks found.")
        sys.exit(0)

    # Sort networks once here
    sorted_networks = sorted(networks, key=lambda x: x.get('signal', -100), reverse=True)

    # Pass the sorted list to display functions
    display_networks(sorted_networks)
    display_signal_strength_graph(sorted_networks)
    log_to_csv(sorted_networks, args.output)


if __name__ == "__main__":
    main()

