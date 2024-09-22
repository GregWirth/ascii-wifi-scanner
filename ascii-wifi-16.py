import subprocess
import re
from collections import defaultdict
from termcolor import colored
from colorama import init
import csv

# Initialize colorama
init()

def detect_wifi_interface():
    """Detects the active WiFi interface using iwconfig."""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "IEEE 802.11" in line:
                return line.split()[0]  # Return the interface name
    except subprocess.CalledProcessError:
        print("Error: Could not run iwconfig. Is wireless-tools installed?")
        return None

def scan_wifi(interface):
    """Scans WiFi networks using the detected interface and returns raw output."""
    result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], capture_output=True, text=True)
    return result.stdout

def parse_wifi_scan(scan_output, show_hidden=True):
    """Parses the scan output to extract SSID, Channel, Frequency, Signal Strength, and Band info."""
    networks = defaultdict(list)
    ssid_re = re.compile(r'ESSID:"(.*?)"')
    channel_re = re.compile(r'Channel:(\d+)')
    signal_re = re.compile(r'Signal level=(-?\d+) dBm')
    freq_re = re.compile(r'Frequency:([\d.]+) GHz')
    enc_re = re.compile(r'Encryption key:(on|off)')
    wpa_re = re.compile(r'(WPA\d?)')  # Adjusted regex to capture WPA, WPA2, WPA3

    current_channel = None
    current_ssid = None
    current_signal = None
    current_freq = None
    current_encryption = None
    current_wpa = "None"  # Default to None if WPA is not found

    for line in scan_output.splitlines():
        channel_match = channel_re.search(line)
        ssid_match = ssid_re.search(line)
        signal_match = signal_re.search(line)
        freq_match = freq_re.search(line)
        enc_match = enc_re.search(line)
        wpa_match = wpa_re.search(line)

        if channel_match:
            current_channel = int(channel_match.group(1))

        if ssid_match:
            current_ssid = ssid_match.group(1).strip() or "[Hidden Network]"

        if signal_match:
            current_signal = int(signal_match.group(1))

        if freq_match:
            current_freq = float(freq_match.group(1))

        if enc_match:
            current_encryption = enc_match.group(1)

        if wpa_match:
            current_wpa = wpa_match.group(1)

        # Only record networks with non-empty SSIDs or hidden if show_hidden is True
        if current_channel and current_ssid and (show_hidden or current_ssid != "[Hidden Network]"):
            band = "2.4 GHz" if current_freq < 3 else "5 GHz"
            networks[current_channel].append(
                (current_ssid, current_signal, current_freq, band, current_encryption, current_wpa))
            current_channel, current_ssid, current_signal, current_freq = None, None, None, None
            current_wpa = "None"  # Reset WPA after each network is processed

    return networks

def signal_color(signal_level):
    """Returns a color based on signal strength, using a gradient from red to green."""
    if signal_level >= -50:
        return colored(f"{signal_level} dBm", "green")  # Strong signal
    elif signal_level >= -60:
        return colored(f"{signal_level} dBm", "yellow")  # Medium signal (better)
    elif signal_level >= -70:
        return colored(f"{signal_level} dBm", "light_yellow")  # Medium signal
    else:
        return colored(f"{signal_level} dBm", "red")  # Weak signal

def signal_bar_graph(signal_level):
    """Returns a colored bar based on signal strength, with more granularity."""
    if signal_level >= -50:
        return colored("█" * 10, "green")  # Strong signal
    elif signal_level >= -60:
        return colored("█" * 8, "yellow")  # Good signal
    elif signal_level >= -70:
        return colored("█" * 6, "light_yellow")  # Medium signal
    else:
        return colored("█" * 4, "red")  # Weak signal

def fancy_header(title):
    """Returns a fancy header with a box around it."""
    return colored(f"\n{'=' * 60}\n{title.center(60)}\n{'=' * 60}", "cyan", attrs=["bold"])

def display_ascii_graph(networks):
    """Displays WiFi networks on channels using ASCII-based graph, sorted by signal strength."""
    print(fancy_header("WiFi Channel Usage"))
    # Sort networks by signal strength
    sorted_networks = sorted(networks.items(), key=lambda x: min([n[1] for n in x[1]]))

    # Print only channels where networks are detected
    for channel, ssids in sorted_networks:
        ssid_display = ", ".join([f"{colored(ssid, 'cyan', attrs=['bold'])} ({signal_color(signal)}, {freq} GHz, {band}, Encryption: {encryption}, WPA: {wpa})"
                                  for ssid, signal, freq, band, encryption, wpa in ssids])
        print(f"Channel {colored(channel, 'yellow', attrs=['bold']):>3}: " + "|" * len(ssids) + f" {ssid_display}")
        print()  # Extra line break for readability
    print("=" * 60)

def display_signal_strength_graph(networks):
    """Displays a color-coded signal strength graph using ASCII bars."""
    print(fancy_header("WiFi Signal Strength Graph"))
    for channel, ssids in networks.items():
        for ssid, signal, freq, band, encryption, wpa in ssids:
            signal_bar = signal_bar_graph(signal)
            print(f"Channel {colored(channel, 'yellow', attrs=['bold']):>3}: {signal_bar} {colored(ssid, 'cyan', attrs=['bold'])} ({signal_color(signal)}, {freq} GHz, {band}, Encryption: {encryption}, WPA: {wpa})")
        print()  # Extra line break for readability
    print("=" * 60)

def log_to_csv(networks, filename='wifi_scan.csv'):
    """Logs the scan results to a CSV file."""
    with open(filename, mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(["Channel", "SSID", "Signal Strength", "Frequency (GHz)", "Band", "Encryption", "WPA"])
        for channel, ssids in networks.items():
            for ssid, signal, freq, band, encryption, wpa in ssids:
                writer.writerow([channel, ssid, signal, freq, band, encryption, wpa])
    print(colored(f"Results logged to {filename}", "green"))

if __name__ == "__main__":
    interface = detect_wifi_interface()
    if interface:
        print(f"Detected WiFi interface: {colored(interface, 'green', attrs=['bold'])}")
        wifi_scan_output = scan_wifi(interface)
        wifi_networks = parse_wifi_scan(wifi_scan_output, show_hidden=True)
        display_ascii_graph(wifi_networks)
        display_signal_strength_graph(wifi_networks)
        log_to_csv(wifi_networks)
    else:
        print(colored("No active WiFi interface detected.", "red", attrs=["bold"]))

