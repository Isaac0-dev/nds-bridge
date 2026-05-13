class BridgePlugin:
    def __init__(self, bridge):
        self.bridge = bridge

    def on_physical_rx(self, raw_frame, src_mac, frame_ctl):
        return raw_frame

    def on_emulated_rx(self, raw_frame, sender_id, channel):
        return raw_frame

    def inject_to_air(self, raw_frame, channel):
        self.bridge._broadcast_over_air(raw_frame, channel)

    def inject_to_lan(self, raw_frame):
        self.bridge._inject_to_lan(raw_frame)
