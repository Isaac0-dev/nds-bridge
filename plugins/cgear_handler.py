from ctypes import *
import struct
from plugins.cgear_action_msg import message_from_action_id


def uint16_string(length):
    class UTF16Array(Array):
        _type_ = c_uint16
        _length_ = length

        def from_str(self, value):
            encoded = value.encode("utf-16-le")
            padded = (encoded + b"\xff\xff" * self._length_)[: self._length_ * 2]
            memmove(addressof(self), padded, self._length_ * 2)

        def to_str(self):
            raw_bytes = bytes(self)
            decoded = raw_bytes.decode("utf-16-le", errors="ignore")
            return decoded.split("\u0000")[0].split("\uffff")[0]

        def __repr__(self):
            return self.to_str()

    return UTF16Array


class AutoStringStructure(LittleEndianStructure):
    def __setattr__(self, name, value):
        if isinstance(value, str):
            try:
                field_obj = getattr(self, name)
                if hasattr(field_obj, "from_str"):
                    field_obj.from_str(value)
                    return
            except AttributeError:
                pass
        super().__setattr__(name, value)


class CGearBeacon(AutoStringStructure):
    PREAMBLE_TEMPLATE = bytes(
        [
            0x0A,
            0x00,
            0x9E,
            0x6A,
            0x01,
            0x00,
            0x01,
            0x00,
            0x80,
            0x13,
            0x00,
            0x00,
            0x0B,
            0x1C,
            0x70,
            0x01,
            0xC4,
            0x00,
            0x30,
            0x00,
            0xA0,
            0x4A,
            0x80,
            0x13,
            0x03,
            0x00,
            0x01,
            0x00,
            0x03,
            0x30,
            0x04,
            0x00,
            0x23,
            0x22,
            0x73,
            0x59,
            0xFF,
            0x00,
        ]
    )

    _pack_ = 1
    _fields_ = [
        # Offsets 0-3
        ("version_bit", c_uint8),
        ("nation", c_uint8),
        ("area", c_uint8),
        ("g_power_id", c_uint8, 7),
        ("sex", c_uint8, 1),
        # Offsets 4-11
        ("suretigai_count", c_uint32, 17),
        ("zone_id", c_uint32, 10),
        ("language", c_uint32, 5),
        ("thanks_recv_count", c_uint32, 17),
        ("send_counter", c_uint32, 5),
        ("townmap_root_zone_id", c_uint32, 10),
        # Offsets 12-15
        ("play_time", c_uint16),  # play_hour:10, play_min:6
        ("trainer_id", c_uint16),
        # Offsets 16-41
        ("name", uint16_string(7)),  # 14 bytes
        ("message", uint16_string(8)),  # 16 bytes (Hardware uses 6 chars)
        # Offsets 42-49
        ("unk_flags", c_uint8 * 6),  # 6 bytes
        ("padding", c_uint16),  # 2 bytes
        # Offsets 50-53
        ("action_no", c_uint16),
        ("monsno", c_uint16),
        # Offsets 54-93
        ("tail", c_uint8 * 36),  # 36 bytes
    ]

    def __init__(
        self,
        name="Hilbert",
        message="Hello!",
        zone=21,
        hour=10,
        minute=0,
        activity=1,
        target=0,
        trainer_id=0x2223,
    ):
        self.name = name
        self.message = message
        self.zone_id = zone
        self.play_hour = hour
        self.play_min = minute
        self.action_no = activity
        self.monsno = target
        self.trainer_id = trainer_id

        # Hardware defaults
        self.version_bit = 0x01
        self.nation = 0x30
        self.language = 2
        self.unk_flags[:] = [0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00]
        self.tail[:] = [0] * 36

    @property
    def play_hour(self):
        return self.play_time & 0x3FF

    @play_hour.setter
    def play_hour(self, value):
        self.play_time = (self.play_time & ~0x3FF) | (value & 0x3FF)

    @property
    def play_min(self):
        return (self.play_time >> 10) & 0x3F

    @play_min.setter
    def play_min(self, value):
        self.play_time = (self.play_time & ~(0x3F << 10)) | ((value & 0x3F) << 10)

    def encode(self, include_preamble=True):
        payload = bytes(self)
        if include_preamble:
            pre = bytearray(self.PREAMBLE_TEMPLATE)
            struct.pack_into("<H", pre, 32, self.trainer_id & 0xFFFF)
            return bytes(pre) + payload
        return payload

    @classmethod
    def decode(cls, data):
        return cls.from_buffer_copy(data[35:])

    def get_activity_str(self):
        return self.ACTIONS.get(self.action_no, f"Unknown ({self.action_no})")

    def __repr__(self):
        return (
            f"Player:[{self.name}] "
            f"Msg:[{self.message}] "
            f"Zone:{self.zone_id} "
            f"Time:{self.play_hour}h{self.play_min}m "
            f"Act:{message_from_action_id(self, self.action_no)} "
            f"Trainer ID:{self.trainer_id:05}"
        )
