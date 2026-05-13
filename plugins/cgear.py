from plugins.base import BridgePlugin
from plugins.cgear_handler import CGearBeacon
from bridge_utils import has_nintendo_vendor_ie

class CGearPlugin(BridgePlugin):
    def __init__(self, bridge):
        super().__init__(bridge)
        self._seen_players = {}

    def on_physical_rx(self, raw_frame, src_mac, frame_ctl):
        subtype = (frame_ctl >> 4) & 0xF
        if subtype == 8:
            if has_nintendo_vendor_ie(raw_frame) and len(raw_frame) > 130:
                try:
                    beacon = CGearBeacon.decode(raw_frame)

                    # Avoid spamming
                    current_repr = repr(beacon)
                    if src_mac not in self._seen_players or self._seen_players[src_mac] != current_repr:
                        print(f"[C-Gear] {src_mac} -> {current_repr}")
                        self._seen_players[src_mac] = current_repr
                except Exception:
                    pass
        return raw_frame
