"""
Offline harness for the CRSF HLA: stubs the Saleae SDK, feeds byte streams
through Hla.decode() and checks what comes back.

Run: python3 tests/test_crsf_hla.py
"""
import os
import sys
import types

# --- stub saleae.analyzers -------------------------------------------------
saleae = types.ModuleType('saleae')
analyzers = types.ModuleType('saleae.analyzers')


class AnalyzerFrame:
    def __init__(self, type, start_time, end_time, data=None):
        self.type = type
        self.start_time = start_time
        self.end_time = end_time
        self.data = data or {}


class HighLevelAnalyzer:
    pass


def _setting(*a, **k):
    return None


analyzers.AnalyzerFrame = AnalyzerFrame
analyzers.HighLevelAnalyzer = HighLevelAnalyzer
analyzers.StringSetting = _setting
analyzers.NumberSetting = _setting
analyzers.ChoicesSetting = _setting
saleae.analyzers = analyzers
sys.modules['saleae'] = saleae
sys.modules['saleae.analyzers'] = analyzers

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from HighLevelAnalyzer import Hla  # noqa: E402


# --- helpers ---------------------------------------------------------------
def crc8(data, poly=0xD5):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def pack_channels(vals):
    """Pack 11 bit values LSB first, exactly as EdgeTX crossfireAssembleChannelData does."""
    bits = 0
    navail = 0
    out = bytearray()
    for v in vals:
        bits |= (v & 0x7FF) << navail
        navail += 11
        while navail >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            navail -= 8
    return bytes(out)


def build_rc_frame(channels, status=None, addr=0xEE):
    payload = bytearray(pack_channels(channels[:16]))
    if status is not None:
        payload.append(status)
    if len(channels) > 16:
        payload += pack_channels(channels[16:32])
    body = bytes([0x16]) + bytes(payload)
    return bytes([addr, len(body) + 1]) + body + bytes([crc8(body)])


def build_frame(ftype, payload, addr=0xC8):
    body = bytes([ftype]) + bytes(payload)
    return bytes([addr, len(body) + 1]) + body + bytes([crc8(body)])


def feed(hla, data):
    """Push raw bytes through the HLA, return the AnalyzerFrames it emits."""
    out = []
    for i, b in enumerate(data):
        f = AnalyzerFrame('data', i, i + 1, {'data': bytes([b])})
        r = hla.decode(f)
        if r is not None:
            out.append(r)
    return out


def new_hla(unit='Digital Value'):
    h = Hla()
    h.channel_unit = unit
    return h


# --- tests -----------------------------------------------------------------
FAILURES = []


def check(name, cond, detail=''):
    if cond:
        print('  PASS  ' + name)
    else:
        print('  FAIL  ' + name + ('  -- ' + detail if detail else ''))
        FAILURES.append(name)


def test_16ch_plain():
    ch = [1000 + i for i in range(16)]
    frames = feed(new_hla(), build_rc_frame(ch))
    payload = [f for f in frames if f.type == 'crsf_payload']
    crc = [f for f in frames if f.type == 'crsf_CRC']
    check('16ch plain: payload emitted', len(payload) == 1)
    check('16ch plain: CRC passes', crc and crc[0].data['crccheck'] == 'Pass',
          crc[0].data['crccheck'] if crc else 'no CRC frame')
    txt = payload[0].data['payload']
    check('16ch plain: labelled 16ch', txt.startswith('[16ch]'), txt[:40])
    for i, v in enumerate(ch, start=1):
        if 'CH{}: {}'.format(i, v) not in txt:
            check('16ch plain: CH{} == {}'.format(i, v), False, txt[:120])
            return
    check('16ch plain: all 16 values decode', True)


def test_16ch_status():
    ch = [500 + i for i in range(16)]
    frames = feed(new_hla(), build_rc_frame(ch, status=0x02))
    payload = [f for f in frames if f.type == 'crsf_payload']
    crc = [f for f in frames if f.type == 'crsf_CRC']
    txt = payload[0].data['payload']
    check('16ch+status: CRC passes', crc and crc[0].data['crccheck'] == 'Pass')
    check('16ch+status: still 16ch', txt.startswith('[16ch]'), txt[:40])
    check('16ch+status: CH5 arming decoded', 'Arming mode: CH5' in txt, txt[-60:])
    check('16ch+status: status not read as a channel',
          'CH17' not in txt, txt[-60:])


def test_32ch():
    ch = [100 + i * 20 for i in range(32)]
    frames = feed(new_hla(), build_rc_frame(ch, status=0x01))
    payload = [f for f in frames if f.type == 'crsf_payload']
    crc = [f for f in frames if f.type == 'crsf_CRC']
    check('32ch: CRC passes', crc and crc[0].data['crccheck'] == 'Pass',
          crc[0].data['crccheck'] if crc else 'no CRC frame')
    txt = payload[0].data['payload']
    check('32ch: labelled 32ch', txt.startswith('[32ch]'), txt[:40])
    check('32ch: switch-mode armed decoded',
          'Arming mode: Switch (armed)' in txt, txt[-60:])
    bad = [i for i, v in enumerate(ch, start=1)
           if 'CH{}: {}'.format(i, v) not in txt]
    check('32ch: all 32 values decode', not bad,
          'bad channels: {}'.format(bad[:6]))


def test_frame_length_byte():
    ch = list(range(32))
    f = build_rc_frame(ch, status=0x00)
    check('32ch: frame is 49 bytes', len(f) == 49, str(len(f)))
    check('32ch: length byte is 47', f[1] == 47, str(f[1]))
    f16 = build_rc_frame(list(range(16)), status=0x00)
    check('16ch: frame is 27 bytes', len(f16) == 27, str(len(f16)))
    check('16ch: length byte is 25', f16[1] == 25, str(f16[1]))


def test_bad_crc():
    ch = [1000] * 32
    f = bytearray(build_rc_frame(ch, status=0x00))
    f[-1] ^= 0xFF
    frames = feed(new_hla(), bytes(f))
    crc = [x for x in frames if x.type == 'crsf_CRC']
    check('corrupt CRC is reported', crc and crc[0].data['crccheck'] == 'Fail')


def test_signed_helpers():
    h = new_hla()
    check('signed16(0xFFFF) == -1', h.unsigned_to_signed_16(0xFFFF) == -1,
          str(h.unsigned_to_signed_16(0xFFFF)))
    check('signed16(0x8000) == -32768', h.unsigned_to_signed_16(0x8000) == -32768,
          str(h.unsigned_to_signed_16(0x8000)))
    check('signed32(0xFFFFFFFF) == -1',
          h.unsigned_to_signed_32(0xFFFFFFFF) == -1,
          str(h.unsigned_to_signed_32(0xFFFFFFFF)))


def test_back_to_back():
    """FSM must resynchronise: two frames in a row."""
    a = build_rc_frame([1000 + i for i in range(16)], status=0x02)
    b = build_rc_frame([200 + i for i in range(32)], status=0x00)
    frames = feed(new_hla(), a + b)
    payload = [f for f in frames if f.type == 'crsf_payload']
    crc = [f for f in frames if f.type == 'crsf_CRC']
    check('back to back: two payloads', len(payload) == 2, str(len(payload)))
    check('back to back: two CRC passes',
          len(crc) == 2 and all(c.data['crccheck'] == 'Pass' for c in crc),
          str([c.data['crccheck'] for c in crc]))
    if len(payload) == 2:
        check('back to back: 16ch then 32ch',
              payload[0].data['payload'].startswith('[16ch]') and
              payload[1].data['payload'].startswith('[32ch]'))


def test_us_units():
    h = new_hla('us')
    frames = feed(h, build_rc_frame([992] * 16, status=0x02))
    txt = [f for f in frames if f.type == 'crsf_payload'][0].data['payload']
    check('centre value renders 1500 us', 'CH1: 1500 us' in txt, txt[:60])
    check('no non-ascii in output', txt.isascii(), repr(txt[:60]))


def test_legacy_unit_setting():
    # a setting saved before the rename must still render sensibly
    h = new_hla('ms')
    frames = feed(h, build_rc_frame([992] * 16, status=0x02))
    txt = [f for f in frames if f.type == 'crsf_payload'][0].data['payload']
    check('legacy "ms" setting falls back to us', 'CH1: 1500 us' in txt, txt[:60])


def test_both_units():
    h = new_hla('Both')
    frames = feed(h, build_rc_frame([992] * 16, status=0x02))
    txt = [f for f in frames if f.type == 'crsf_payload'][0].data['payload']
    check('Both shows value and us', 'CH1: 992 (1500 us)' in txt, txt[:60])


def test_radio_id_sync():
    """0xC8 sync frame: type 0x3A, sub type 0x10, big endian 100ns units."""
    # 4000 us interval (250 Hz), -100 us offset
    payload = bytes([0xEA, 0x00, 0x10]) + (40000).to_bytes(4, 'big') + \
        (-1000).to_bytes(4, 'big', signed=True)
    frame = build_frame(0x3A, payload)
    check('sync: frame is 15 bytes', len(frame) == 15, str(len(frame)))
    check('sync: length byte is 13', frame[1] == 13, str(frame[1]))

    frames = feed(new_hla(), frame)
    pay = [f for f in frames if f.type == 'crsf_payload']
    crc = [f for f in frames if f.type == 'crsf_CRC']
    check('sync: CRC passes', crc and crc[0].data['crccheck'] == 'Pass')
    txt = pay[0].data['payload'] if pay else '(none)'
    check('sync: not reported as an error',
          'Error in Type' not in txt and not pay[0].data.get('error'), txt[:70])
    check('sync: interval decoded', 'interval 4000.0 us' in txt, txt[:90])
    check('sync: rate decoded', '250.0 Hz' in txt, txt[:90])
    check('sync: offset decoded', 'offset -100.0 us' in txt, txt[:90])
    check('sync: destination decoded', 'Radio Transmitter' in txt, txt[:90])


def test_gps_big_endian():
    payload = (488584000).to_bytes(4, 'big', signed=True) + \
        (22945000).to_bytes(4, 'big', signed=True) + \
        (123).to_bytes(2, 'big') + (18000).to_bytes(2, 'big') + \
        (1500).to_bytes(2, 'big') + bytes([12])
    frames = feed(new_hla(), build_frame(0x02, payload))
    txt = [f for f in frames if f.type == 'crsf_payload'][0].data['payload']
    check('gps: latitude', '48.8584' in txt, txt[:90])
    check('gps: longitude', '2.2945' in txt, txt[:90])
    check('gps: ground speed', '12.3' in txt, txt[:110])
    check('gps: heading', '180.0' in txt, txt[:130])
    check('gps: altitude', '500m' in txt, txt[-60:])
    check('gps: satellites', '12' in txt, txt[-30:])


def test_gps_negative_coordinates():
    """Southern/western hemispheres need correct sign handling."""
    payload = (-338523000).to_bytes(4, 'big', signed=True) + \
        (-704279000).to_bytes(4, 'big', signed=True) + \
        (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + \
        (1000).to_bytes(2, 'big') + bytes([7])
    frames = feed(new_hla(), build_frame(0x02, payload))
    txt = [f for f in frames if f.type == 'crsf_payload'][0].data['payload']
    check('gps: negative latitude', '-33.8523' in txt, txt[:90])
    check('gps: negative longitude', '-70.4279' in txt, txt[:90])


def test_attitude_big_endian():
    payload = (1000).to_bytes(2, 'big', signed=True) + \
        (-2000).to_bytes(2, 'big', signed=True) + \
        (31415).to_bytes(2, 'big', signed=True)
    frames = feed(new_hla(), build_frame(0x1E, payload))
    txt = [f for f in frames if f.type == 'crsf_payload'][0].data['payload']
    check('attitude: pitch 0.1 rad', '0.1' in txt, txt[:80])
    check('attitude: roll -0.2 rad', '-0.2' in txt, txt[:80])
    check('attitude: yaw 3.1415 rad', '3.1415' in txt, txt[:80])


def test_heart_beat_address():
    frames = feed(new_hla(), build_frame(0x0B, bytes([0x00, 0xC8])))
    f = [x for x in frames if x.type == 'crsf_payload'][0]
    check('heartbeat: device resolved', 'Flight Controller' in f.data['payload'],
          f.data['payload'])
    check('heartbeat: no unknown-device error', not f.data.get('error'),
          repr(f.data.get('error')))


def test_undecoded_type_is_not_an_error():
    frames = feed(new_hla(), build_frame(0x0C, bytes([0x00, 0x01, 0x02, 0x03])))
    f = [x for x in frames if x.type == 'crsf_payload'][0]
    check('undecoded type names the frame', 'RPM' in f.data['payload'],
          f.data['payload'])
    check('undecoded type is not flagged as an error', not f.data.get('error'),
          repr(f.data.get('error')))


for t in (test_16ch_plain, test_16ch_status, test_32ch, test_frame_length_byte,
          test_bad_crc, test_signed_helpers, test_back_to_back, test_us_units,
          test_legacy_unit_setting, test_both_units, test_radio_id_sync,
          test_gps_big_endian, test_gps_negative_coordinates,
          test_attitude_big_endian, test_heart_beat_address,
          test_undecoded_type_is_not_an_error):
    print(t.__name__ + ':')
    t()

print()
if FAILURES:
    print('{} FAILED: {}'.format(len(FAILURES), ', '.join(FAILURES)))
    sys.exit(1)
print('all checks passed')
