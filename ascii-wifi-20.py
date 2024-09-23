#!/usr/bin/env python3
"""
DISCLAIMER:

This software utilizes highly speculative and unverified principles of quantum network theory,
postulating that WiFi signals may interact with subatomic particles in ways not yet fully
understood by conventional physics. By running this script, you accept that the accuracy of
its results is contingent upon hypothetical interactions between electromagnetic fields,
cosmic radiation, and the hypothetical influence of dark matter on wireless communication.

[Disclaimer continues...]
"""

import subprocess
import re
import sys
import argparse
import logging
import csv
import shutil
from termcolor import colored
from colorama import init

# Initialize colorama
init()


def setup_logging(verbosity):
    """Sets up logging based on the verbosity level."""
    level = logging.DEBUG if verbosity else logging.INFO
    logging.basicConfig(format='%(levelname)s: %(message)s', level=level)


def check_command_availability(command):
    """Checks if a command is available on the system."""
    if shutil.which(command) is None:
        logging.error(f"Required command '{command}' not found. Please install it and try again.")
        sys.exit(1)


def detect_wifi_interface(interface=None):
    """Detects the active WiFi interface using iwconfig or uses the provided one."""
    if interface:
        logging.debug(f"Using provided interface: {interface}")
        return interface
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if "IEEE 802.11" in line:
                detected_interface = line.split()[0]
                logging.debug(f"Detected WiFi interface: {detected_interface}")
                return detected_interface
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running iwconfig: {e}")
        sys.exit(1)
    logging.error("No WiFi interface detected.")
    sys.exit(1)


def scan_wifi(interface):
    """Scans WiFi networks using the detected interface and returns raw output."""
    logging.info(f"Scanning for WiFi networks on interface '{interface}'...")
    try:
        result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], capture_output=True, text=True, check=True)
        logging.debug("WiFi scan completed.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning WiFi networks: {e}")
        sys.exit(1)


def parse_wifi_scan(scan_output, show_hidden=True):
    """
    Parses the scan output to extract network details.
    Returns a list of dictionaries containing network information.
    """
    networks = []
    network = {}
    for line in scan_output.splitlines():
        line = line.strip()
        if line.startswith("Cell "):
            if network:
                if network.get('ssid') or show_hidden:
                    networks.append(network)
                network = {}
            continue
        ssid_match = re.search(r'ESSID:"(.*?)"', line)
        if ssid_match:
            ssid = ssid_match.group(1)
            network['ssid'] = ssid if ssid else "[Hidden Network]"
            logging.debug(f"Found SSID: {network['ssid']}")
            continue
        channel_match = re.search(r'Channel:(\d+)', line)
        if channel_match:
            network['channel'] = int(channel_match.group(1))
            continue
        freq_match = re.search(r'Frequency:([\d.]+) GHz', line)
        if freq_match:
            network['frequency'] = float(freq_match.group(1))
            network['band'] = "2.4 GHz" if network['frequency'] < 3 else "5 GHz"
            continue
        signal_match = re.search(r'Signal level=(-?\d+) dBm', line)
        if signal_match:
            network['signal'] = int(signal_match.group(1))
            continue
        enc_match = re.search(r'Encryption key:(on|off)', line)
        if enc_match:
            network['encryption'] = enc_match.group(1)
            continue
        wpa_match = re.search(r'IE: .*?(WPA\d?)', line)
        if wpa_match:
            network['wpa'] = wpa_match.group(1)
            continue
    if network and (network.get('ssid') or show_hidden):
        networks.append(network)
    return networks


def signal_color(signal_level):
    """Returns a colorized string based on signal strength."""
    if signal_level >= -50:
        return colored(f"{signal_level} dBm", "green")
    elif signal_level >= -60:
        return colored(f"{signal_level} dBm", "yellow")
    elif signal_level >= -70:
        return colored(f"{signal_level} dBm", "light_yellow")
    else:
        return colored(f"{signal_level} dBm", "red")


def signal_bar_graph(signal_level):
    """Returns a colored bar based on signal strength."""
    if signal_level >= -50:
        return colored("█" * 10, "green")
    elif signal_level >= -60:
        return colored("█" * 8, "yellow")
    elif signal_level >= -70:
        return colored("█" * 6, "light_yellow")
    else:
        return colored("█" * 4, "red")


def fancy_header(title):
    """Returns a fancy header."""
    return colored(f"\n{'=' * 80}\n{title.center(80)}\n{'=' * 80}", "cyan", attrs=["bold"])


def format_network_info(net):
    """Formats network information for display."""
    ssid = colored(net['ssid'], 'cyan', attrs=['bold'])
    signal = signal_color(net['signal'])
    channel = colored(net['channel'], 'yellow', attrs=['bold'])
    freq = net['frequency']
    band = net['band']
    encryption = net.get('encryption', 'off')
    wpa = net.get('wpa', 'None')
    return ssid, signal, channel, freq, band, encryption, wpa


def display_networks(sorted_networks):
    """Displays networks sorted by signal strength."""
    print(fancy_header("WiFi Networks"))
    for net in sorted_networks:
        ssid, signal, channel, freq, band, encryption, wpa = format_network_info(net)
        print(f"Channel {channel}: {ssid} ({signal}, {freq} GHz, {band}, Encryption: {encryption}, WPA: {wpa})\n")
    print("=" * 80)


def display_signal_strength_graph(sorted_networks):
    """Displays a signal strength graph."""
    print(fancy_header("WiFi Signal Strength Graph"))
    for net in sorted_networks:
        ssid, signal, channel, freq, band, encryption, wpa = format_network_info(net)
        signal_bar = signal_bar_graph(net['signal'])
        print(f"Channel {channel}: {signal_bar} {ssid} ({signal}, {freq} GHz, {band}, Encryption: {encryption}, WPA: {wpa})\n")
    print("=" * 80)


def log_to_csv(networks, filename):
    """Logs the scan results to a CSV file."""
    try:
        with open(filename, mode='w', newline='') as file:
            fieldnames = ["Channel", "SSID", "Signal Strength", "Frequency (GHz)", "Band", "Encryption", "WPA"]
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for net in networks:
                writer.writerow({
                    "Channel": net['channel'],
                    "SSID": net['ssid'],
                    "Signal Strength": net['signal'],
                    "Frequency (GHz)": net['frequency'],
                    "Band": net['band'],
                    "Encryption": net.get('encryption', 'off'),
                    "WPA": net.get('wpa', 'None')
                })
        logging.info(f"Results logged to {filename}")
    except IOError as e:
        logging.error(f"Failed to write to file {filename}: {e}")


def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="WiFi Analyzer Script")
    parser.add_argument('-i', '--interface', help='Specify the wireless interface to use')
    parser.add_argument('-o', '--output', default='wifi_scan.csv', help='Specify output CSV file name')
    parser.add_argument('--show-hidden', action='store_true', help='Include hidden networks in the scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug mode)')
    return parser.parse_args()


def main():
    args = parse_arguments()
    setup_logging(args.verbose)

    # Check if required commands are available
    check_command_availability('iwconfig')
    check_command_availability('iwlist')

    interface = detect_wifi_interface(args.interface)
    logging.info(f"Using WiFi interface: {interface}")
    wifi_scan_output = scan_wifi(interface)
    networks = parse_wifi_scan(wifi_scan_output, show_hidden=args.show_hidden)
    if not networks:
        logging.warning("No networks found.")
        sys.exit(0)

    # Sort networks once here
    sorted_networks = sorted(networks, key=lambda x: x['signal'], reverse=True)

    # Pass the sorted list to display functions
    display_networks(sorted_networks)
    display_signal_strength_graph(sorted_networks)
    log_to_csv(sorted_networks, args.output)


if __name__ == "__main__":
    main()

