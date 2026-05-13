import sys
import os
import re
import time
import struct
import threading
import importlib.util
import concurrent.futures
import hashlib
from datetime import datetime
from collections import deque
import queue
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

from scapy.all import sniff, sendp, RadioTap

try:
    import enet
except ImportError:
    print("Error: The 'enet' python package is required.")
    print("Run: sudo pip install enet")
    exit(1)

from bridge_utils import (
    has_nintendo_vendor_ie,
    set_channel,
    mac_to_str,
    NDS_CHANNELS,
    KNOWN_NINTENDO_MACS,
    setup_monitor_mode,
    teardown_monitor_mode,
    setup_virtual_monitor,
    teardown_virtual_monitor,
    check_monitor_mode,
    is_primary_interface,
    melonds_header_from_dot11,
    _frame_type_str,
    detect_wireless_iface,
)

MELONDS_PORT = 7064
MAGIC_LANP = 0x504E414C
MAGIC_NIFI = 0x4946494E
VERSION = 1

CMD_CLIENTINIT = 1
CMD_PLAYERINFO = 2
CMD_PLAYERLIST = 3
CMD_PLAYERCONNECT = 4
CMD_PLAYERDISCONNECT = 5

# PlayerStatus enum (must match LAN.h)
PLAYER_NONE = 0
PLAYER_CLIENT = 1
PLAYER_HOST = 2
PLAYER_CONNECTING = 3
PLAYER_DISCONNECTED = 4

# sizeof(Player) in melonDS — must be 52 bytes
# struct Player { int ID; char Name[32]; PlayerStatus Status; u32 Address; bool IsLocalPlayer; u8 pad[3]; u32 Ping; };
SIZEOF_PLAYER = 52



class PluginManager:
    def __init__(self, bridge, plugin_dir="plugins"):
        self.bridge = bridge
        self.plugin_dir = plugin_dir
        self.plugins = []
        self._mtimes = {}
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._watchdog_thread.start()

    def _watchdog_loop(self):
        while True:
            time.sleep(2)
            if not os.path.exists(self.plugin_dir):
                continue

            changed = False
            for filename in os.listdir(self.plugin_dir):
                if filename.endswith(".py") and filename != "__init__.py" and filename != "base.py":
                    filepath = os.path.join(self.plugin_dir, filename)
                    try:
                        mtime = os.path.getmtime(filepath)
                        if self._mtimes.get(filepath) != mtime:
                            self._mtimes[filepath] = mtime
                            changed = True
                    except OSError:
                        pass

            if changed and self.plugins:
                self.load_plugins(quiet=True)

    def load_plugins(self, quiet=False):
        if not os.path.exists(self.plugin_dir):
            return

        new_plugins = []
        if not quiet:
            print(f"[*] Loading plugins from {self.plugin_dir}...")
        else:
            print(f"[*] Reloading plugins due to file change...")

        for filename in sorted(os.listdir(self.plugin_dir)):
            if filename.endswith(".py") and filename != "__init__.py" and filename != "base.py":
                module_name = filename[:-3]
                file_path = os.path.join(self.plugin_dir, filename)

                try:
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Look for classes that inherit from BridgePlugin
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type) and attr_name != "BridgePlugin":
                            # Basic check for our interface (duck typing or isinstance)
                            if hasattr(attr, "on_physical_rx") and hasattr(attr, "on_emulated_rx"):
                                plugin_instance = attr(self.bridge)
                                new_plugins.append(plugin_instance)
                                if not quiet:
                                    print(f"  [+] Loaded plugin: {attr_name} ({module_name})")
                except Exception as e:
                    print(f"  [!] Failed to load plugin {module_name}: {e}")
        self.plugins = new_plugins

    def dispatch_physical_rx(self, raw_frame, src_mac, frame_ctl):
        for plugin in self.plugins:
            try:
                raw_frame = plugin.on_physical_rx(raw_frame, src_mac, frame_ctl)
                if raw_frame is None:
                    return None
            except Exception as e:
                print(f"[!] Plugin {plugin.__class__.__name__} error in physical_rx: {e}")
        return raw_frame

    def dispatch_emulated_rx(self, raw_frame, sender_id, channel):
        for plugin in self.plugins:
            try:
                raw_frame = plugin.on_emulated_rx(raw_frame, sender_id, channel)
                if raw_frame is None:
                    return None
            except Exception as e:
                print(f"[!] Plugin {plugin.__class__.__name__} error in emulated_rx: {e}")
        return raw_frame


class LANBridge:
    def log(self, text):
        t = datetime.now().strftime("%H:%M:%S")
        if not text.startswith("["):
            text = f"[{t}] {text}"
        elif not text.startswith(f"[{t}]"):
            # Try to replace existing time tags or just prepend if it has a [!] type prefix
            if re.match(r"^\[\d\d:\d\d:\d\d\]", text):
                pass
            else:
                text = f"[{t}] {text}"
        self.ui_logs.append(text)

    def __init__(
        self,
        iface,
        channels,
        enable_injection=True,
        verbose=False,
        host="127.0.0.1",
        is_server=False,
        parent_iface=None,
    ):
        self.ui_logs = deque(maxlen=20)
        self.iface = iface
        self.parent_iface = parent_iface
        self.channels = channels or NDS_CHANNELS
        self.enable_injection = enable_injection
        self.verbose = verbose

        self.running = False
        self.current_channel = self.channels[0]
        self.is_server = is_server

        if self.is_server:
            # Become the Room Host Server
            address = enet.Address(None, MELONDS_PORT)
            try:
                self.host = enet.Host(address, 16, 2, 0, 0)
            except MemoryError:
                self.log(f"[!] Critical Error: Port {MELONDS_PORT} is already in use!")
                self.log(
                    f"[*] Close the program hosting a room on this port so this script "
                    f"can take over the port, or run without --server to join the existing room."
                )
                sys.exit(1)

            self.log(f"[*] Started Net-NDS Server on port {MELONDS_PORT}")
            self.player_id = 0
            self.connected_to_room = True

            # Room state
            self.clients = {}  # peer -> pID
            self.player_infos = {}  # pID -> player struct bytes (52 bytes)
            self.connected_bitmask = 0
        else:
            # Client Mode
            self.host = enet.Host(None, 1, 2, 0, 0)
            self.log(f"[*] Attaching to melonDS LAN Server at {host}:{MELONDS_PORT} ...")
            self.peer = self.host.connect(
                enet.Address(host.encode("ascii"), MELONDS_PORT), 2
            )
            self.player_id = -1
            self.connected_to_room = False
            self.player_infos = {}
            self.connected_bitmask = 0

        self.emulated_macs = set()

        # Stats
        self.physical_rx_count = 0
        self.emulated_rx_count = 0
        self.emulated_tx_count = 0
        self.melonds_lan_tx_count = 0

        # Threading & Hopping state
        self.sniff_thread = None
        self.hop_thread = None
        self.last_detection_time = 0
        self.burst_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

        # Deduplication cache
        self.seen_frames = {}

        # ENet Thread-Safety Send Queue
        self.enet_send_queue = queue.Queue()

        # Plugin System
        self.plugin_manager = PluginManager(self)
        self.plugin_manager.load_plugins()

    def poll_enet(self, timeout=10):
        # Process pending outbound enet packets
        while not self.enet_send_queue.empty():
            full_packet = self.enet_send_queue.get()
            enet_packet = enet.Packet(full_packet, enet.PACKET_FLAG_UNSEQUENCED)
            try:
                if self.is_server:
                    self.host.broadcast(1, enet_packet)
                else:
                    self.peer.send(1, enet_packet)
            except OSError:
                pass

        event = self.host.service(timeout)
        if event is None:
            return

        if event.type == enet.EVENT_TYPE_CONNECT:
            if self.is_server:
                self._handle_server_connect(event)
            else:
                self.log("[+] Connected to melonDS ENet Router!")
        elif event.type == enet.EVENT_TYPE_RECEIVE:
            if self.is_server:
                self._handle_server_packet(event)
            else:
                self._handle_client_packet(event)
        elif event.type == enet.EVENT_TYPE_DISCONNECT:
            if self.is_server:
                self._handle_server_disconnect(event)
            else:
                self.log("[!] Disconnected from LAN Room.")
                self.connected_to_room = False

    # --- Server Logic ---
    def _handle_server_connect(self, event):
        pid = -1
        # Find first available player ID from 1 to 15 (0 is host)
        used_ids = set(self.clients.values())
        for i in range(1, 16):
            if i not in used_ids:
                pid = i
                break

        if pid == -1:
            self.log(f"[!] Rejected connection: server full (15 players reached).")
            event.peer.disconnect()
            return

        self.clients[event.peer] = pid
        self.log(f"New ENet peer connected, assigned Player #{pid}")

        # Handshake: ClientInit
        cmd = struct.pack("<B I I B B", CMD_CLIENTINIT, MAGIC_LANP, VERSION, pid, 16)
        packet = enet.Packet(cmd, enet.PACKET_FLAG_RELIABLE)
        event.peer.send(0, packet)

    def _handle_server_disconnect(self, event):
        if event.peer in self.clients:
            pid = self.clients[event.peer]
            was_authenticated = pid in self.player_infos
            del self.clients[event.peer]
            if pid in self.player_infos:
                name = self._get_player_name(pid) or f"Player #{pid}"
                del self.player_infos[pid]
                self.connected_bitmask &= ~(1 << pid)
                self.log(f"Player #{pid} ({name}) disconnected.")
                self._broadcast_player_list()
            else:
                self.log(f"Unauthenticated peer #{pid} disconnected.")
        else:
            self.log(f"Unknown peer disconnected.")

    def _handle_server_packet(self, event):
        channel = event.channelID
        data = event.packet.data
        peer = event.peer

        if peer not in self.clients:
            return
        pid = self.clients[peer]

        if channel == 0:  # Command Channel
            cmd_type = data[0]
            if cmd_type == CMD_PLAYERINFO:
                # Validate: packet must be 9 + sizeof(Player) = 61 bytes
                if len(data) != 9 + SIZEOF_PLAYER:
                    self.log(f"[!] Player #{pid} sent malformed PlayerInfo ({len(data)} bytes, expected {9 + SIZEOF_PLAYER})")
                    return
                # Validate magic and version
                magic, version = struct.unpack("<II", data[1:9])
                if magic != MAGIC_LANP or version != VERSION:
                    self.log(f"[!] Player #{pid} sent bad magic/version, disconnecting.")
                    peer.disconnect()
                    return
                # Extract the Player struct and validate the ID
                player_data = bytearray(data[9:9 + SIZEOF_PLAYER])
                player_id_in_struct = struct.unpack("<i", player_data[0:4])[0]
                if player_id_in_struct != pid:
                    self.log(f"[!] Player #{pid} ID mismatch (got {player_id_in_struct}), disconnecting.")
                    peer.disconnect()
                    return
                # Override Status to Player_Client and Address to peer's address
                struct.pack_into("<i", player_data, 36, PLAYER_CLIENT)  # Status at offset 36
                try:
                    import socket
                    addr_bytes = socket.inet_aton(str(peer.address.host))
                    addr_int = struct.unpack("<I", addr_bytes)[0]
                except Exception:
                    addr_int = 0x0100007F  # fallback to 127.0.0.1
                struct.pack_into("<I", player_data, 40, addr_int)  # Address at offset 40
                self.player_infos[pid] = bytes(player_data)
                self.log(f"[+] Player #{pid} authenticated.")
                self._broadcast_player_list()
            elif cmd_type == CMD_PLAYERCONNECT:
                self.connected_bitmask |= (1 << pid)
                self.log(f"[+] Player #{pid} is now connected (ready for MP).")
            elif cmd_type == CMD_PLAYERDISCONNECT:
                self.connected_bitmask &= ~(1 << pid)
                self.log(f"[*] Player #{pid} disconnected from MP.")
        elif channel == 1:  # MP Channel
            if len(data) < 24:
                return

            magic, sender_id, pkt_type, length, timestamp = struct.unpack(
                "<I I I I Q", data[:24]
            )
            if magic == MAGIC_NIFI:
                # Forward NIFI to all other internet peers
                for client_peer in self.clients:
                    if client_peer != peer:
                        try:
                            # Forward exact NIFI packet untouched
                            packet = enet.Packet(data, enet.PACKET_FLAG_UNSEQUENCED)
                            client_peer.send(1, packet)
                        except:
                            pass

                # Bridge it directly into our local physical airspace
                if len(data) >= 24 + length:
                    wifi_buffer = data[24 : 24 + length]
                    if len(wifi_buffer) > 12:
                        raw_frame = wifi_buffer[12:]
                        ch = wifi_buffer[9]
                        self.emulated_rx_count += 1

                        if len(raw_frame) >= 16:
                            mac = mac_to_str(raw_frame[10:16])
                            if mac not in self.emulated_macs:
                                self.log(f"[+] Learned remote MAC: {mac} (Anti-loopback)")
                                self.emulated_macs.add(mac)

                        frame_ctl = struct.unpack("<H", raw_frame[0:2])[0] if len(raw_frame) >= 2 else 0
                        type_str = _frame_type_str(frame_ctl)
                        if self.emulated_rx_count <= 5 or self.emulated_rx_count % 50 == 0:
                            self.log(f"Emu RX #{self.emulated_rx_count}: {type_str} {len(raw_frame)}B ch{ch} from player #{sender_id}")

                        # Plugin Hook
                        raw_frame = self.plugin_manager.dispatch_emulated_rx(raw_frame, sender_id, ch)
                        if raw_frame is not None:
                            self._broadcast_over_air(raw_frame, ch)

    def _broadcast_player_list(self):
        # Only count the host + authenticated players (those who sent PlayerInfo)
        num_players = 1 + len(self.player_infos)
        cmd = bytearray()
        cmd.append(CMD_PLAYERLIST)
        cmd.append(num_players)

        # 16 players * 52 bytes = 832 bytes (must match sizeof(Players) in melonDS)
        players_buf = bytearray(16 * SIZEOF_PLAYER)
        # Player 0 = us (the server host). Status must be Player_Host (2).
        p0_data = struct.pack(
            "<i 32s i I ? 3x I", 0, b"Server Host (Net-NDS)\x00", PLAYER_HOST, 0x0100007F, False, 0
        )
        players_buf[0:SIZEOF_PLAYER] = p0_data

        for pid, info in self.player_infos.items():
            if len(info) == SIZEOF_PLAYER:
                players_buf[pid * SIZEOF_PLAYER : (pid + 1) * SIZEOF_PLAYER] = info

        cmd.extend(players_buf)
        packet = enet.Packet(bytes(cmd), enet.PACKET_FLAG_RELIABLE)
        self.host.broadcast(0, packet)

    # --- Client Logic ---
    def _handle_client_packet(self, event):
        channel = event.channelID
        data = event.packet.data
        if channel == 0:
            cmd_type = data[0]
            if cmd_type == CMD_CLIENTINIT and len(data) >= 11:
                magic, version = struct.unpack("<II", data[1:9])
                if magic == MAGIC_LANP and version == VERSION:
                    self.player_id = data[9]
                    self.log(
                        f"[*] Handshake received! We are Virtual Player #{self.player_id}"
                    )
                    self._send_player_info()
                    self._send_player_connect()
                    self.connected_to_room = True
            elif cmd_type == CMD_PLAYERLIST:
                num_players = data[1]
                self.log(f"Room Size: {num_players} players connected.")
                if len(data) == 2 + 16 * SIZEOF_PLAYER:
                    self.player_infos.clear()
                    for i in range(16):
                        offset = 2 + i * SIZEOF_PLAYER
                        info = bytes(data[offset:offset + SIZEOF_PLAYER])
                        status = struct.unpack_from("<i", info, 36)[0]
                        if status != PLAYER_NONE:
                            self.player_infos[i] = info
        elif channel == 1:
            if len(data) < 24:
                return

            magic, sender_id, pkt_type, length, timestamp = struct.unpack(
                "<I I I I Q", data[:24]
            )
            if magic == MAGIC_NIFI and sender_id != self.player_id:
                if len(data) >= 24 + length:
                    wifi_buffer = data[24 : 24 + length]
                    if len(wifi_buffer) > 12:
                        raw_frame = wifi_buffer[12:]
                        ch = wifi_buffer[9]
                        self.emulated_rx_count += 1

                        if len(raw_frame) >= 16:
                            mac = mac_to_str(raw_frame[10:16])
                            if mac not in self.emulated_macs:
                                self.log(f"[+] Learned remote MAC: {mac} (Anti-loopback)")
                                self.emulated_macs.add(mac)

                        frame_ctl = struct.unpack("<H", raw_frame[0:2])[0] if len(raw_frame) >= 2 else 0
                        type_str = _frame_type_str(frame_ctl)
                        if self.emulated_rx_count <= 5 or self.emulated_rx_count % 50 == 0:
                            self.log(f"Emu RX #{self.emulated_rx_count}: {type_str} {len(raw_frame)}B ch{ch} from player #{sender_id}")

                        # Plugin Hook
                        raw_frame = self.plugin_manager.dispatch_emulated_rx(raw_frame, sender_id, ch)
                        if raw_frame is not None:
                            self._broadcast_over_air(raw_frame, ch)

    def _send_player_info(self):
        player_data = struct.pack(
            "<i 32s i I ? 3x I",
            self.player_id,
            b"Physical DS (via Bridge)\x00",
            1,
            0x0100007F,
            False,
            0,
        )
        cmd = struct.pack("<B I I", CMD_PLAYERINFO, MAGIC_LANP, VERSION) + player_data
        packet = enet.Packet(cmd, enet.PACKET_FLAG_RELIABLE)
        self.peer.send(0, packet)

    def _send_player_connect(self):
        cmd = struct.pack("<B", CMD_PLAYERCONNECT)
        packet = enet.Packet(cmd, enet.PACKET_FLAG_RELIABLE)
        self.peer.send(0, packet)

    # --- Bridging and Injection ---
    def _inject_to_lan(self, raw_frame):
        if not self.connected_to_room:
            return

        for ch in self.channels:
            wifi_buffer = melonds_header_from_dot11(raw_frame, channel=ch, rate=0x0A)
            timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
            nifi_header = struct.pack(
                "<I I I I Q",
                MAGIC_NIFI,
                self.player_id,
                0,
                len(wifi_buffer),
                timestamp_ms,
            )
            full_packet = nifi_header + wifi_buffer

            self.enet_send_queue.put(full_packet)

        self.melonds_lan_tx_count += 3

    def _burst_inject(self, raw_frame):
        self._inject_to_lan(raw_frame)

        def burst_task():
            for _ in range(4):
                if not self.running:
                    break
                time.sleep(0.04)
                self._inject_to_lan(raw_frame)

        self.burst_executor.submit(burst_task)

    def _broadcast_over_air(self, raw_frame, channel):
        if not self.enable_injection:
            return
        is_locked = len(self.channels) == 1
        if not is_locked and channel != self.current_channel:
            set_channel(self.iface, channel)
            self.current_channel = channel
            time.sleep(0.01)  # Allow hardware to stabilize after channel switch

        try:
            pkt = RadioTap() / raw_frame
            sendp(pkt, iface=self.iface, verbose=False)
            self.emulated_tx_count += 1
            if self.emulated_tx_count <= 3 or self.emulated_tx_count % 50 == 0:
                t = datetime.now().strftime("%H:%M:%S")
                ch_note = f"ch{self.current_channel}"
                if channel != self.current_channel:
                    ch_note += f" (tagged ch{channel})"
                print(
                    f"[{t}] Broadcast to physical DS: {len(raw_frame)}B {ch_note} [#{self.emulated_tx_count}]"
                )
        except OSError:
            pass

    def _sniff_loop(self):
        def process_packet(pkt):
            raw_frame = bytes(pkt)
            if len(raw_frame) < 4:
                return
            rt_len = struct.unpack("<H", raw_frame[2:4])[0]
            if len(raw_frame) <= rt_len:
                return
            raw_dot11 = raw_frame[rt_len:]
            if len(raw_dot11) < 24:
                return

            frame_ctl = struct.unpack("<H", raw_dot11[0:2])[0]
            frame_type = (frame_ctl >> 2) & 0x3
            src_mac = mac_to_str(raw_dot11[10:16])

            # Anti-loopback
            if src_mac in self.emulated_macs:
                return

            has_nintendo = has_nintendo_vendor_ie(raw_dot11)
            if has_nintendo and src_mac not in KNOWN_NINTENDO_MACS:
                KNOWN_NINTENDO_MACS.add(src_mac)

            if src_mac[:8] == "00:09:bf" or src_mac in KNOWN_NINTENDO_MACS:
                now = time.time()
                self.last_detection_time = now

                # Deduplication
                frame_hash = hashlib.md5(raw_dot11).digest()
                if frame_hash in self.seen_frames and now - self.seen_frames[frame_hash] < 0.2:
                    return  # Drop duplicate
                self.seen_frames[frame_hash] = now

                # Cleanup old hashes
                if len(self.seen_frames) > 100:
                    cutoff = now - 0.5
                    self.seen_frames = {k: v for k, v in self.seen_frames.items() if v > cutoff}

                self.physical_rx_count += 1

                t = datetime.now().strftime("%H:%M:%S")
                type_str = _frame_type_str(frame_ctl)
                print(
                    f"[{t}] Sniffed Physical DS {type_str} -> ENet Room [total: {self.physical_rx_count}]"
                )

                # Plugin Hook
                raw_dot11 = self.plugin_manager.dispatch_physical_rx(raw_dot11, src_mac, frame_ctl)
                if raw_dot11 is None:
                    return

                if frame_type == 0:
                    self._burst_inject(raw_dot11)
                else:
                    self._inject_to_lan(raw_dot11)

        import subprocess
        while self.running:
            try:
                sniff(iface=self.iface, prn=process_packet, store=0, stop_filter=lambda x: not self.running)
            except Exception as e:
                err_str = str(e)
                if "Operation not permitted" in err_str:
                    self.log("[*] Physical DS sniffing requires root (sudo).")
                    self.log("[*] Running in emulator-only mode — only melonDS LAN connections will work.")
                    return  # Exit the sniff thread cleanly
                elif "Network is down" in err_str or "No such device" in err_str:
                    if self.running:
                        self.log(f"[*] Link lost ({err_str}). Attempting to recover {self.iface}...")
                        if self.parent_iface:
                            subprocess.run(["iw", "dev", self.parent_iface, "interface", "add", self.iface, "type", "monitor"], capture_output=True)
                        subprocess.run(["ip", "link", "set", self.iface, "up"], capture_output=True)
                        if self.parent_iface:
                            set_channel(self.iface, self.current_channel)
                            self.log(f"[+] Recovered virtual monitor {self.iface}")
                        else:
                            self.log(f"[+] Interface {self.iface} is back up")
                        time.sleep(1)
                else:
                    self.log(f"Sniff error: {e}")

    def _channel_hop_loop(self):
        base_dwell = 0.5
        idx = 0
        while self.running:
            time.sleep(base_dwell)
            if not self.running:
                break

            # Adaptive dwell: wait longer if we recently detected something
            if time.time() - self.last_detection_time < 2.0:
                continue

            idx = (idx + 1) % len(self.channels)
            chan = self.channels[idx]
            set_channel(self.iface, chan)
            self.current_channel = chan

    def _get_player_name(self, pid):
        """Extract player name from stored player info struct."""
        if pid in self.player_infos:
            info = self.player_infos[pid]
            # Name is at offset 4, 32 bytes
            name_bytes = info[4:36]
            return name_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return None

    def generate_dashboard(self):
        # --- Status Table ---
        table = Table(title="LAN Bridge Status", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Mode", "Host Server" if self.is_server else "Client")

        if self.connected_to_room:
            table.add_row("Connection", "[bold green]Connected[/bold green]")
        else:
            table.add_row("Connection", "[bold yellow]Connecting...[/bold yellow]")

        if self.is_server:
            # Count only authenticated players (those who sent PlayerInfo) + the host
            num_authenticated = 1 + len(self.player_infos)
            num_pending = len(self.clients) - len(self.player_infos)
            count_str = str(num_authenticated)
            if num_pending > 0:
                count_str += f" (+{num_pending} pending)"
            table.add_row("Players", count_str)
        else:
            table.add_row("Player ID", f"#{self.player_id}" if self.player_id >= 0 else "\u2014")
            table.add_row("Players", str(len(self.player_infos)))

        table.add_row("Emu RX (from room)", str(self.emulated_rx_count))
        table.add_row("Emu TX (to room)", str(self.melonds_lan_tx_count))

        if self.physical_rx_count > 0 or self.emulated_tx_count > 0:
            table.add_row("Physical RX", str(self.physical_rx_count))
            table.add_row("Physical TX", str(self.emulated_tx_count))

        plugins_str = ", ".join(p.__class__.__name__ for p in self.plugin_manager.plugins) or "None"
        table.add_row("Plugins", plugins_str)

        # --- Player List Table ---
        player_table = Table(title="Players", box=box.SIMPLE)
        player_table.add_column("#", style="dim")
        player_table.add_column("Name", style="green")
        player_table.add_column("Type", style="cyan")
        player_table.add_column("MACs", style="yellow")

        for pid, info in sorted(self.player_infos.items()):
            name = self._get_player_name(pid) or f"Player #{pid}"
            status = struct.unpack_from("<i", info, 36)[0]
            ptype = "[bold]Host[/bold]" if status == PLAYER_HOST else "Emulator"

            # Highlight our own player
            if not self.is_server and pid == self.player_id:
                ptype += " (You)"
                name = f"[bold]{name}[/bold]"

            player_table.add_row(str(pid), name, ptype, "\u2014")

        known_macs = ", ".join(self.emulated_macs) if self.emulated_macs else "\u2014"
        player_table.add_row("", f"[dim]Known MACs: {known_macs}[/dim]", "", "")

        # --- Log Panel ---
        recent_logs = list(self.ui_logs)[-7:]
        log_text = "\n".join(recent_logs) if recent_logs else "Waiting for events..."
        log_panel = Panel(log_text, title="Recent Events", box=box.ROUNDED)

        layout = Layout()
        layout.split_column(
            Layout(table, size=13),
            Layout(player_table, size=6 + len(self.player_infos)),
            Layout(log_panel)
        )
        return layout

    def start(self):
        self.running = True
        set_channel(self.iface, self.current_channel)

        # Always use the TUI unless explicitly disabled (can add a flag later)
        use_tui = True
        console = Console()

        print(f"[*] LAN Bridge started on {self.iface}")

        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

        if len(self.channels) > 1:
            self.hop_thread = threading.Thread(
                target=self._channel_hop_loop, daemon=True
            )
            self.hop_thread.start()

        if use_tui:
            try:
                with Live(self.generate_dashboard(), console=console, refresh_per_second=4, screen=True) as live:
                    while self.running:
                        self.poll_enet(timeout=10)
                        live.update(self.generate_dashboard())
            except KeyboardInterrupt:
                self.running = False
            finally:
                print("\n[*] Shutting down LAN Bridge...")
        else:
            try:
                while self.running:
                    self.poll_enet(timeout=10)
            except KeyboardInterrupt:
                print("\n[*] Shutting down LAN Bridge...")
                self.running = False

    def stop(self):
        self.running = False


def run_lan_bridge(
    iface,
    channels,
    enable_injection=True,
    verbose=False,
    setup_monitor=False,
    virtual_monitor=False,
    host="127.0.0.1",
    is_server=False,
):
    parent_iface = None
    vdev_name = "mon0"

    if virtual_monitor:
        parent_iface = iface
        iface = vdev_name
        if not setup_virtual_monitor(parent_iface, vdev_name):
            print("[!] Failed to set up virtual monitor mode. Aborting.")
            return
    elif setup_monitor:
        if not setup_monitor_mode(iface):
            print("[!] Failed to set up monitor mode. Aborting.")
            return

    bridge = LANBridge(
        iface, channels, enable_injection, verbose, host=host, is_server=is_server, parent_iface=parent_iface
    )
    try:
        bridge.start()
    finally:
        if virtual_monitor:
            teardown_virtual_monitor(vdev_name)
        elif setup_monitor:
            teardown_monitor_mode(iface)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Net-NDS Wireless Bridge")
    parser.add_argument(
        "--iface", "-i", default=None, help="Wireless interface (auto-detected if omitted)"
    )
    parser.add_argument(
        "--channels", "-c", default="1,7,13", help="Comma-separated scan channels"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help=" melonDS or Net-NDS room IP address"
    )
    parser.add_argument(
        "--server", action="store_true", help="Host a room (acts as the ENet Router)"
    )
    parser.add_argument(
        "--setup-monitor", action="store_true", help="Auto-configure monitor mode on the specified interface"
    )
    parser.add_argument(
        "--virtual-monitor", "--vmon", action="store_true", help="Create a virtual monitor interface (leaves parent in managed mode)"
    )
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args()

    channels = [int(c.strip()) for c in args.channels.split(",")]

    iface = args.iface
    if iface is None:
        iface = detect_wireless_iface()
        if iface is None:
            print("[!] No wireless interface found. Specify one with --iface.")
            sys.exit(1)
        print(f"[*] Auto-detected wireless interface: {iface}")

    # Prompt user if no monitor mode is configured and interface is not in monitor mode
    if not args.setup_monitor and not args.virtual_monitor:
        if not check_monitor_mode(iface):
            is_primary = is_primary_interface(iface)
            print(f"\n[*] Interface {iface} is currently in managed mode.")
            if is_primary:
                print("[!] This appears to be your primary network interface.")

            print("\nHow would you like to proceed?")
            print(f"  1) Use Virtual Monitor (mon0) [Recommended for {iface}]")
            print(f"  2) Setup Full Monitor Mode (will disconnect internet)")
            print(f"  3) Continue anyway (packets may not be captured)")

            try:
                choice = input("\nChoice [1-3]: ").strip()
                if choice == "1":
                    args.virtual_monitor = True
                elif choice == "2":
                    args.setup_monitor = True
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Aborting.")
                sys.exit(0)

    run_lan_bridge(
        iface,
        channels,
        verbose=not args.quiet,
        setup_monitor=args.setup_monitor,
        virtual_monitor=args.virtual_monitor,
        host=args.host,
        is_server=args.server,
    )
