import os
import struct
import subprocess
import platform

# Dynamically populated set of specific MAC addresses (bytes) that we've seen
# transmitting Nintendo Vendor IEs. This helps support 3DS/2DS consoles with
# unknown OUIs.
KNOWN_NINTENDO_MACS = set()

# Nintendo vendor-specific IE OUI (found inside tag 0xDD)
NINTENDO_VS_OUI = b"\x00\x09\xbf\x00"

# Commonly used channels
NDS_CHANNELS = [1, 7, 13]


# 802.11 frame type names for logging
FRAME_TYPE_NAMES = {0: "Mgmt", 1: "Ctrl", 2: "Data", 3: "Ext"}
MGMT_SUBTYPE_NAMES = {
    0: "AssocReq",
    1: "AssocResp",
    2: "ReassocReq",
    3: "ReassocResp",
    4: "ProbeReq",
    5: "ProbeResp",
    6: "Timing Advertisement",
    7: "Reserved",
    8: "Beacon",
    9: "ATIM",
    10: "Disassoc",
    11: "Auth",
    12: "Deauth",
    13: "Action",
    14: "Action No Ack",
    15: "Reserved",
}


def detect_wireless_iface():
    """
    Auto-detect the first wireless interface on the system.
    Checks /sys/class/net/*/wireless for wireless capability.
    Returns the interface name, or None if not found.
    """
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return None

    for iface in sorted(os.listdir(net_dir)):
        wireless_dir = os.path.join(net_dir, iface, "wireless")
        if os.path.isdir(wireless_dir):
            return iface
    return None


def check_monitor_mode(iface):
    try:
        result = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
        return "type monitor" in result.stdout
    except:
        return False


def is_primary_interface(iface):
    """Check if the given interface is the system's primary route (has default gateway)."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        # Look for 'default via ... dev iface'
        return f"dev {iface}" in result.stdout and "default" in result.stdout
    except:
        return False


def _frame_type_str(frame_ctl):
    ftype = (frame_ctl >> 2) & 0x3
    subtype = (frame_ctl >> 4) & 0xF
    type_name = FRAME_TYPE_NAMES.get(ftype, f"Type{ftype}")
    if ftype == 0:
        sub_name = MGMT_SUBTYPE_NAMES.get(subtype, f"Sub{subtype}")
        return f"{type_name}/{sub_name}"
    return f"{type_name}/Sub{subtype}"


def has_nintendo_vendor_ie(frame_bytes):
    if len(frame_bytes) < 36:
        return False

    # Beacon fixed params are 12 bytes after the 24-byte MAC header
    ie_data = frame_bytes[36:]
    offset = 0
    while offset + 2 <= len(ie_data):
        eid = ie_data[offset]
        elen = ie_data[offset + 1]
        if offset + 2 + elen > len(ie_data):
            break
        if eid == 0xDD and elen >= 4:
            if ie_data[offset + 2 : offset + 6] == NINTENDO_VS_OUI:
                # We found a Nintendo IE! Dynamically register this MAC as Nintendo
                if len(frame_bytes) >= 16:
                    mac = frame_bytes[10:16]
                    KNOWN_NINTENDO_MACS.add(mac)
                return True
        offset += 2 + elen
    return False


def melonds_header_from_dot11(raw_frame, channel, rate=0x0A):
    header = bytearray(12)
    header[0] = 0x01  # status/flags
    header[8] = rate
    header[9] = channel & 0xFF
    struct.pack_into("<H", header, 10, len(raw_frame))
    return bytes(header) + raw_frame


def mac_to_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def check_injection_support(iface):
    try:
        # aireplay-ng --test would be ideal but requires the interface to be up
        # For now, just check if the iface exists and is in monitor mode
        result = subprocess.run(
            ["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5
        )
        return "type monitor" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def setup_monitor_mode(iface):
    """
    Enable monitor mode on the given wireless interface.
    1. Kill conflicting processes
    2. Set the interface down
    3. Set type to monitor
    4. Bring it back up
    Needs root.
    """
    print(f"[*] Setting up monitor mode on {iface}...")
    current_os = platform.system()

    if current_os == "Windows":

        # Path to Npcap's WlanHelper utility
        wlan_helper = r"C:\Windows\System32\Npcap\WlanHelper.exe"

        try:
            check_cmd = [wlan_helper, iface, "mode"]
            res = subprocess.run(check_cmd, capture_output=True, text=True, check=True)
            print(f"[*] Current mode: {res.stdout.strip()}")

            set_cmd = [wlan_helper, iface, "mode", "monitor"]
            subprocess.run(set_cmd, capture_output=True, text=True)

        except FileNotFoundError:
            print("[!] Error: Npcap WlanHelper.exe not found.")
            print("[!] Please install Npcap with 'Support raw 802.11 traffic'.")
            return False
    if current_os == "Linux":
        commands = [
            # Kill processes that might interfere
            ["airmon-ng", "check", "kill"],
            # Bring interface down
            ["ip", "link", "set", iface, "down"],
            # Set monitor mode
            ["iw", iface, "set", "type", "monitor"],
            # Bring it back up
            ["ip", "link", "set", iface, "up"],
        ]

        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0 and cmd[0] != "airmon-ng":
                    print(
                        f"[!] Warning: {' '.join(cmd)} returned {result.returncode}: {result.stderr.strip()}"
                    )
            except FileNotFoundError:
                if cmd[0] == "airmon-ng":
                    # airmon-ng is optional, fall through to iw-based setup
                    continue
                print(f"[!] Command not found: {cmd[0]}")
                return None
            except subprocess.TimeoutExpired:
                print(f"[!] Timeout running: {' '.join(cmd)}")
                return None

        # Verify monitor mode is active
        if check_injection_support(iface):
            print(f"[+] Monitor mode active on {iface}")
            return iface
        else:
            print(f"[!] Failed to verify monitor mode on {iface}")
            return None


def setup_virtual_monitor(parent_iface, vdev_name="mon0"):
    print(f"[*] Setting up virtual monitor {vdev_name} on {parent_iface}...")

    # Try to delete it first just in case it's lingering
    subprocess.run(["iw", "dev", vdev_name, "del"], capture_output=True)

    commands = [
        ["iw", "dev", parent_iface, "interface", "add", vdev_name, "type", "monitor"],
        ["ip", "link", "set", vdev_name, "up"],
    ]

    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print(f"[!] Warning: {' '.join(cmd)} returned {result.returncode}: {result.stderr.strip()}")
                return None
        except FileNotFoundError:
            print(f"[!] Command not found: {cmd[0]}")
            return None
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout running: {' '.join(cmd)}")
            return None

    if check_injection_support(vdev_name):
        print(f"[+] Virtual monitor mode active on {vdev_name}")
        return vdev_name
    else:
        print(f"[!] Failed to verify virtual monitor mode on {vdev_name}")
        return None

def set_channel(iface, channel):
    try:
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def teardown_monitor_mode(iface):
    print(f"[*] Restoring {iface} to managed mode...")
    commands = [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "type", "managed"],
        ["ip", "link", "set", iface, "up"],
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Try to restart NetworkManager
    try:
        subprocess.run(
            ["systemctl", "start", "NetworkManager"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    print(f"[+] {iface} restored to managed mode")


def teardown_virtual_monitor(vdev_name):
    print(f"[*] Tearing down virtual monitor {vdev_name}...")
    try:
        subprocess.run(["iw", "dev", vdev_name, "del"], capture_output=True, text=True, timeout=5)
        print(f"[+] {vdev_name} deleted")
    except Exception as e:
        print(f"[!] Failed to delete {vdev_name}: {e}")

