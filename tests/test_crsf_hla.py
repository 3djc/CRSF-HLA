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


for t in (test_16ch_plain, test_16ch_status, test_32ch, test_frame_length_byte,
          test_bad_crc, test_signed_helpers, test_back_to_back, test_us_units,
          test_legacy_unit_setting, test_both_units):
    print(t.__name__ + ':')
    t()

print()
if FAILURES:
    print('{} FAILED: {}'.format(len(FAILURES), ', '.join(FAILURES)))
    sys.exit(1)
print('all checks passed')
