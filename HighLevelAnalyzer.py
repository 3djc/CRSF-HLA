# CRSF Frame Parser
# Saleae Logic 2 High Level Analyzer for the Crossfire (CRSF) protocol, as used
# by TBS Crossfire, Tracer, ExpressLRS and EdgeTX.
#
# Copyright 2022, Max Gröning
# Copyright 2023-2024, Ansh Chawla
# Copyright 2026, 3djc
# SPDX-License-Identifier: Apache-2.0

import enum
import math
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


class Hla(HighLevelAnalyzer):
    # List of types this analyzer produces
    result_types = {
        'crsf_address_byte': {
            'format': 'Going to: {{data.destination}}({{data.address}})'
        },
        'crsf_length_byte': {
            'format': 'Length: {{data.length}} ({{data.error}})'
        },
        'crsf_type_byte': {
            'format': 'Type: {{data.type}} ({{data.error}})'
        },
        'crsf_payload': {
            'format': 'Payload: {{data.payload}}'
        },
        'crsf_CRC': {
            'format': 'CRC Check: {{data.crccheck}}'
        },
        'crsf_error': {
            'format': '{{data.error}}'
        }
    }

    # Decoder FSM
    class dec_fsm_e(enum.Enum):
        Idle = 1
        # Sync_Byte = 2  # No being used - If sync byte is detected the state changes from Idle -> Length
        Length = 3
        Type = 4
        Payload = 5

    # CRSF frame types
    frame_types = {
        0x02: 'GPS',
        0x03: 'GPS time',
        0x07: 'Vario',
        0x08: 'Battery sensor',
        0x09: 'Baro altitude',
        0x0A: 'Airspeed',
        0x0B: 'Heart Beat',
        0x0C: 'RPM',
        0x0D: 'Temperature',
        0x0E: 'Cells',
        0x10: 'OpenTX sync',
        0x14: 'Link statistics',
        # no plans of implmenting https://github.com/betaflight/betaflight/blob/master/src/main/rx/crsf.c#L170
        0x1c: 'Link statistics Rx',
        # no plans of implmenting https://github.com/betaflight/betaflight/blob/master/src/main/rx/crsf.c#L181
        0x1d: 'Link statistics Tx',
        0x16: 'RC channels packed',
        0x17: 'Subset RC channels packed',
        0x1E: 'Attitude',
        0x21: 'Flight mode',
        0x28: 'Ping devices',
        0x29: 'Device info',
        0x2A: 'Request settings',
        0x2B: 'Parameter settings entry',
        0x2C: 'Parameter Read',
        0x2D: 'Parameter Write',
        0x32: 'Command',
        0x3A: 'Radio id',
        0x78: 'KISS request',
        0x79: 'KISS respond',
        0x7A: 'MSP request',
        0x7B: 'MSP respond',
        0x7C: 'MSP Write',
        0x80: 'Arduipilot respond'
    }  # Extended Header Frames, range: 0x28 to 0x96

    # https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CrsfProtocol/crsf_protocol.h#L108
    # Size of payload only not including CRC and type
    frame_types_sizes = {
        0x02: (15, 15),
        0x07: (2, 2),
        0X0b: (1, 1),
        0x08: (8, 8),
        0x09: (4, 4),
        0x1E: (6, 6),
        0x29: (48, 48),
        0x21: (4, 16),
        # 22 = 16ch, 23 = 16ch + EdgeTX status byte, 45 = 32ch + status byte
        0x16: (22, 45)
    }
    # Protocol defines
    # https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CrsfProtocol/crsf_protocol.h#L119
    CRSF_ADDRESSES = {b'\xc8': 'Flight Controller',
                      b'\xea': 'Radio Transmitter',
                      b'\xee': 'CRSF Transmitter',
                      b'\xec': 'CRSF Receiver',
                      b'\x00': 'CRSF Broadcast',
                      b'\xc0': 'Current sensor',
                      b'\xc2': 'GPS',
                      b'\xcc': 'Race Tag',
                      b'\xEF': 'ELRS LUA',
                      b'\x10': 'USB',
                      b'\xc4': 'TBS Black Box',
                      b'\x80': 'TBS CORE PNP PRO',
                      b'\x8A': 'Reserved 1',
                      b'\xCA': 'Reserved 2'}

    # Same table keyed by int, for addresses carried inside a payload
    CRSF_ADDRESSES_BY_INT = {k[0]: v for k, v in CRSF_ADDRESSES.items()}

    # Subset RC (0x17) resolution configuration: bits per channel and the
    # scale used to convert to microseconds. See Betaflight src/main/rx/crsf.h
    SUBSET_RC_RES = {
        0: (10, 1.0),
        1: (11, 0.5),
        2: (12, 0.25),
        3: (13, 0.125),
    }

    # Uplink TX power is sent as an index into this table, in mW
    TX_POWER_MW = [0, 10, 25, 100, 500, 1000, 2000, 250, 50]

    # Settings:
    channel_unit_options = ['us', 'Digital Value', 'Both']
    channel_unit = ChoicesSetting(channel_unit_options)

    def __init__(self):
        '''
        Initializes the CRFS HLA.
        '''
        self.crsf_packet_start = None
        self.crsf_new_packet_start = None  # Timestamp: Start of frame
        self.dec_fsm = self.dec_fsm_e.Idle  # Current state of protocol decoder FSM
        self.crsf_frame_length = 0  # No. of bytes (type + payload + CRC)
        self.crsf_frame_type = None  # Type of current frame (see frame_types)
        self.crsf_frame_current_index = 0  # Index to determine end of payload
        # Stores the payload for decoding after last byte ist rx'd.
        self.crsf_payload = []
        # Timestamp: Start of payload (w/o frame type)
        self.crsf_payload_start = None
        self.crsf_payload_end = None  # Timestamp: End of payload

        # print("Initialized CRSF HLA.")

    def unsigned_to_signed_8(self, x):
        '''
        Little helper to get a signed value from a byte.
        '''
        if x > 127:
            x -= 256
        return x

    def unsigned_to_signed_16(self, x):
        '''
        Little helper to get a signed value from a 2 bytes.
        '''
        if x > 32767:  # x > 2**15 -1
            x -= 65536
        return x

    def unsigned_to_signed_32(self, x):
        '''
        Little helper to get a signed value from a 4 bytes.
        '''
        if x > 2**31-1:  # x > 2**31 -1
            x -= 2**32
        return x

    def unpack_bits(self, data, bits, count=None):
        '''
        Unpacks values of the given width, packed LSB first, from a block of bytes.
        '''
        bin_str = ''
        for i in data:
            bin_str += format(i, '08b')[::-1]
        if count is None:
            count = len(bin_str) // bits
        values = []
        for i in range(count):
            chunk = bin_str[bits * i: bits * (i + 1)]
            if len(chunk) < bits:
                break
            values.append(int(chunk[::-1], 2))
        return values

    def unpack_channels(self, data):
        '''
        Unpacks 11 bit channel values from a block of bytes (22 bytes -> 16 channels).
        '''
        return self.unpack_bits(data, 11)

    def format_channel_values(self, pairs, first_channel=1):
        '''
        Renders (raw, microseconds) pairs according to the unit setting.
        '''
        parts = []
        for i, (value, value_us) in enumerate(pairs):
            ch = first_channel + i
            if self.channel_unit == 'Digital Value':
                parts.append('CH{}: {}'.format(ch, value))
            elif self.channel_unit == 'Both':
                parts.append('CH{}: {} ({} us)'.format(ch, value, value_us))
            else:
                parts.append('CH{}: {} us'.format(ch, value_us))
        return ', '.join(parts)

    def describe_arming_status(self, status):
        '''
        EdgeTX status byte: bit 0 = armed (Switch mode), bit 1 = CH5 arming mode.
        '''
        if status is None:
            return ''
        if status & 0x02:
            return 'Arming mode: CH5'
        return 'Arming mode: Switch ({})'.format(
            'armed' if status & 0x01 else 'disarmed')

    def decode(self, frame: AnalyzerFrame):
        '''
        Processes a frame from the async analyzer, returns an AnalyzerFrame with result_types or nothing.

        Feed it with async analyzer frames. :)
        '''

        self.crsf_frame_start = frame.start_time  # variable reused to decode error
        self.crsf_frame_end = frame.end_time
        # CRSF bits in packet are littleednian
        try:
            # New frame
            if self.crsf_new_packet_start == None and frame.data['data'] in self.CRSF_ADDRESSES.keys() and self.dec_fsm == self.dec_fsm_e.Idle:
                self.crsf_new_packet_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.Length
                dest = self.CRSF_ADDRESSES[frame.data['data']]
                return AnalyzerFrame('crsf_address_byte', frame.start_time, frame.end_time, {'address': f"{format(int.from_bytes(frame.data['data'] ,byteorder='little'),'#x')}",
                                                                                             'destination': f"{dest}"})

            # Length
            if self.dec_fsm == self.dec_fsm_e.Length:
                payload = int.from_bytes(
                    frame.data['data'], byteorder='little')
                self.crsf_frame_length = payload
                self.dec_fsm = self.dec_fsm_e.Type
                if self.crsf_frame_length < 2:  # error handling
                    self.crsf_new_packet_start = None
                    self.dec_fsm = self.dec_fsm_e.Idle
                    self.crsf_frame_length = 0
                    self.crsf_frame_type = None
                    self.crsf_frame_current_index = 0
                    self.crsf_payload = []
                    self.crsf_payload_start = None
                    self.crsf_payload_end = None
                    return AnalyzerFrame('crsf_length_byte', frame.start_time, frame.end_time, {
                    'length': str(payload),
                    'error' : "length cannot be less than 2"
                })

                elif self.crsf_frame_length > 63:
                    analyzerframe = AnalyzerFrame('crsf_length_byte', frame.start_time, frame.end_time, {
                        'length': str(payload),
                        'error': "length cannot be greater than 63"
                    })

                    # And initialize again for next frame
                    self.crsf_new_packet_start = None
                    self.dec_fsm = self.dec_fsm_e.Idle
                    self.crsf_frame_length = 0
                    self.crsf_frame_type = None
                    self.crsf_frame_current_index = 0
                    self.crsf_payload = []
                    self.crsf_payload_start = None
                    self.crsf_payload_end = None
                    return analyzerframe
                
                return AnalyzerFrame('crsf_length_byte', frame.start_time, frame.end_time, {
                    'length': str(payload)
                })

            # Type
            if self.dec_fsm == self.dec_fsm_e.Type:
                payload = int.from_bytes(
                    frame.data['data'], byteorder='little')
                self.crsf_frame_type = payload
                self.dec_fsm = self.dec_fsm_e.Payload
                self.crsf_frame_current_index += 1
                min_len = 0
                max_len = 100  # setting to be greater than max payload size
                if self.crsf_frame_type in self.frame_types_sizes.keys():
                    # if min max size defined then match length
                    min_len, max_len = self.frame_types_sizes[self.crsf_frame_type]

                if payload in self.frame_types.keys():
                    return AnalyzerFrame('crsf_type_byte', frame.start_time, frame.end_time, {
                        'type': self.frame_types[payload],
                        'error': f"{f'''Length doesn't correspond to type'''if not min_len<= self.crsf_frame_length -2 <=max_len else ''}"
                    })
                else:
                    # And initialize again for next frame
                    self.crsf_new_packet_start = None
                    self.dec_fsm = self.dec_fsm_e.Idle
                    self.crsf_frame_length = 0
                    self.crsf_frame_type = None
                    self.crsf_frame_current_index = 0
                    self.crsf_payload = []
                    self.crsf_payload_start = None
                    self.crsf_payload_end = None

                    return AnalyzerFrame('crsf_type_byte', frame.start_time, frame.end_time, {
                        'type': "Unrecognised",
                        'error': "Unrecognised type"
                    })

            # Payload
            if self.dec_fsm == self.dec_fsm_e.Payload:

                # to do
                # implement time out of some sort
                # maybe we compare bytes received with time passed

                payload = int.from_bytes(
                    frame.data['data'], byteorder='little')

                if self.crsf_frame_current_index == 1:  # First payload byte
                    self.crsf_payload_start = frame.start_time
                    self.crsf_payload.append(payload)
                    self.crsf_frame_current_index += 1
                    #print('Payload start ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
                # ... still collecting payload bytes ...
                elif self.crsf_frame_current_index < (self.crsf_frame_length - 2):
                    self.crsf_payload.append(payload)
                    self.crsf_frame_current_index += 1
                    self.crsf_payload_end = frame.end_time
                    #print('Adding payload ({}): {:2x}'.format(self.crsf_frame_current_index, payload))

                elif self.crsf_frame_current_index == self.crsf_frame_length - 2:
                    # second last byte received
                    # whole payload received
                    self.crsf_payload.append(payload)
                    self.crsf_frame_current_index += 1
                    self.crsf_payload_end = frame.end_time
                    if self.crsf_frame_type == 0x08:  # Battery sensor
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L260
                        bin_str = ''
                        for i in self.crsf_payload:
                            # Format as bits and reverse order
                            bin_str += format(i, '08b')
                        # print(bin_str)
                        # 2 bytes - Voltage (mV * 100) BigEndian
                        Voltage = int(bin_str[0:16], 2)/10
                        # 2 bytes - Current (mA * 100)
                        Current = int(bin_str[16:32], 2)/10
                        # 3 bytes - Capacity (mAh)
                        Capacity = int(bin_str[32:56], 2)
                        # 1 byte  - Remaining (%)
                        Battery_percentage = int(bin_str[56:64],2)
                        payload_str = f"Voltage: {'%.2f' % Voltage}V ,Current: {'%.2f' % Current}A ,Capacity: {'%.2f' % Capacity}mAh ,Battery %: {'%.2f' % Battery_percentage}"
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x14:  # Link statistics
                        # https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CrsfProtocol/crsf_protocol.h#L312
                        payload_signed = self.crsf_payload.copy()
                        # Uplink SNR and ...
                        payload_signed[3] = self.unsigned_to_signed_8(
                            payload_signed[3])
                        # ... download SNR are signed.
                        payload_signed[9] = self.unsigned_to_signed_8(
                            payload_signed[9])
                        # uplink TX power is an index into a table of mW values
                        payload_signed[6] = self.TX_POWER_MW[payload_signed[6]] \
                            if payload_signed[6] < len(self.TX_POWER_MW) else 0
                        # One byte per entry...
                        payload_str = ('Uplink RSSI 1: -{}dB, ' +
                                       'Uplink RSSI 2: -{}dB, ' +
                                       'Uplink Link Quality: {}%, ' +
                                       'Uplink SNR: {}dB, ' +
                                       'Active Antenna: {}, ' +
                                       'RF Mode: {}, ' +
                                       'Uplink TX Power: {} mW, ' +
                                       'Downlink RSSI: -{}dB, ' +
                                       'Downlink Link Quality: {}%, ' +
                                       'Downlink SNR: {}dB').format(*payload_signed)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x10:  # OpenTX sync
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': "Sync frame, normally carried inside a Radio ID (0x3A) frame"
                        })
                        # ToDo
                        # 4 bytes - Adjusted Refresh Rate
                        # 4 bytes - Last Update
                        # 2 bytes - Refresh Rate
                        # 1 bytes (signed) - Refresh Rate
                        # 2 bytes - Input Lag
                        # 1 byte  - Interval
                        # 1 byte  - Target
                        # 1 byte  - Downlink RSSI
                        # 1 byte  - Downlink Link Quality
                        # 1 byte (signed) Downling SNR
                    elif self.crsf_frame_type == 0x21:                         # flight mode
                        # max 16 bytes
                        # Format: String = [ACRO , WAIT , !FS! , RTH , MANU , STAB , HOR , AIR , !ERR] + *(if disarmed) + \0
                        # eg: AIR* -> Air mode and disarmed
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L367
                        return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'Flight Mode: ' + ''.join([chr(i) for i in self.crsf_payload]) + f'''{"  ( disarmed )" if chr(self.crsf_payload[-2]) == '*' else "( Armed )"}''',
                            'error': ""})
                    elif self.crsf_frame_type == 0x02:  # GPS
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L237
                        # Payload:
                        # int32_t     Latitude ( degree / 10`000`000 )
                        # int32_t     Longitude (degree / 10`000`000 )
                        # uint16_t    Groundspeed ( km/h / 10 )
                        # uint16_t    GPS heading ( degree / 100 )
                        # uint16      Altitude ( meter ­1000m offset )
                        # uint8_t     Satellites in use ( counter )
                        d = bytes(self.crsf_payload)
                        latitude = int.from_bytes(d[0:4], 'big', signed=True)
                        longitude = int.from_bytes(d[4:8], 'big', signed=True)
                        groundspeed = int.from_bytes(d[8:10], 'big')
                        gps_heading = int.from_bytes(d[10:12], 'big')
                        gps_altitude = int.from_bytes(d[12:14], 'big')
                        satellities = d[14]
                        return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': f'Latitude (degrees): {latitude/1e7} ,Longitude (degrees): {longitude/1e7} ,Ground Speed (Km/h): {groundspeed/10} , Gps Heading (Degree): {gps_heading/100} ,Gps altitude: {gps_altitude-1000}m ,Satellites :{satellities}',
                            'error': ""})
                    elif self.crsf_frame_type == 0x0B:  # HEART BEAT
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L288
                        address = int.from_bytes(
                            bytes(self.crsf_payload[0:2]), 'big')
                        if address in self.CRSF_ADDRESSES_BY_INT.keys():
                            return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                                'payload': f'Origin: {self.CRSF_ADDRESSES_BY_INT[address]}',
                                'error': ""
                            })
                        else:
                            return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                                'payload': f'Origin: {format(address, "#x")} (unknown device address)',
                                'error': "Unknown device"
                            })
                    elif self.crsf_frame_type == 0x28:  # Ping
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L300
                        dest_address = self.crsf_payload[0]
                        src_address = self.crsf_payload[1]
                        if src_address in self.CRSF_ADDRESSES_BY_INT.keys() and dest_address in self.CRSF_ADDRESSES_BY_INT.keys():
                            return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                                'payload': f'Destination: {self.CRSF_ADDRESSES_BY_INT[dest_address]} ,Origin: {self.CRSF_ADDRESSES_BY_INT[src_address]}',
                                'error': "",
                                'destination': f'{format(dest_address, "#x")}'})
                        else:
                            return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                                'payload': f'Destination: {format(dest_address, "#x")} ,Origin: {format(src_address, "#x")} (unknown devices)',
                                'error': "Unknown device",
                                'destination': f'{format(dest_address, "#x")}'})

                    elif self.crsf_frame_type == 0x1E:  # Attitude
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L337
                        d = bytes(self.crsf_payload)
                        pitch = int.from_bytes(d[0:2], 'big', signed=True) / 10000
                        roll = int.from_bytes(d[2:4], 'big', signed=True) / 10000
                        yaw = int.from_bytes(d[4:6], 'big', signed=True) / 10000
                        return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': f'Pitch(rad): {pitch} ,Roll(rad): {roll} ,Yaw(rad): {yaw}',
                            'error': ""})
                    elif self.crsf_frame_type == 0x29:  # Device info
                        # https://github.com/betaflight/betaflight/blob/master/src/main/telemetry/crsf.c#L412

                        dest = self.crsf_payload[0]
                        origin = self.crsf_payload[1]
                        index = 2
                        device_name = ''
                        while index < len(self.crsf_payload) and self.crsf_payload[index] != 0:
                            device_name += chr(self.crsf_payload[index])
                            index = index+1
                        index = index + 12 + 1  # 12 null bytes are sent after null terminated string
                        device_info_paramter_count = self.crsf_payload[index]
                        device_info_paramter_version = self.crsf_payload[index+1]
                        return AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': f'Destination: {format(dest,"#x")} ,Origin: {format(origin,"#x")} ,Device Name: {device_name} ,Device info parameter count: {device_info_paramter_count} ,Device info paramter version: {device_info_paramter_version}',
                            'error': ""})
                    elif self.crsf_frame_type == 0x07:  # Vario
                        # int16 vertical speed in cm/s
                        vspd = int.from_bytes(
                            bytes(self.crsf_payload[0:2]), 'big', signed=True)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'Vertical speed: {} m/s'.format(vspd / 100)
                        })
                    elif self.crsf_frame_type == 0x03:  # GPS time
                        # uint16 year, then month, day, hour, minute, second,
                        # and a uint16 millisecond
                        d = bytes(self.crsf_payload)
                        year = int.from_bytes(d[0:2], 'big')
                        ms = int.from_bytes(d[7:9], 'big') if len(d) >= 9 else 0
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'GPS time: {:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}'.format(
                                year, d[2], d[3], d[4], d[5], d[6], ms)
                        })
                    elif self.crsf_frame_type == 0x09:  # Baro altitude
                        # Bit 15 set: the remainder is metres. Otherwise the
                        # value is decimetres with a 10000 offset. A third byte
                        # is a TBS vario, four or more an ELRS vario.
                        d = bytes(self.crsf_payload)
                        raw = int.from_bytes(d[0:2], 'big')
                        if raw & 0x8000:
                            altitude = raw & 0x7FFF
                        else:
                            altitude = (raw - 10000) / 10
                        payload_str = 'Altitude: {} m'.format(round(altitude, 2))
                        if len(d) == 3:
                            v = self.unsigned_to_signed_8(d[2])
                            sign = -1 if v < 0 else 1
                            # exponential scale, see EdgeTX crossfire.cpp
                            vspd = ((math.exp(abs(v) * 0.026) - 1) * 100) * sign
                            payload_str += ' ,Vertical speed: {} m/s'.format(
                                round(vspd / 100, 2))
                        elif len(d) > 3:
                            vspd = int.from_bytes(d[2:4], 'big', signed=True)
                            payload_str += ' ,Vertical speed: {} m/s'.format(
                                vspd / 100)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x0A:  # Airspeed
                        # uint16 in 0.1 km/h
                        speed = int.from_bytes(
                            bytes(self.crsf_payload[0:2]), 'big')
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'Airspeed: {} km/h'.format(speed / 10)
                        })
                    elif self.crsf_frame_type == 0x0C:  # RPM
                        # source id, then one or more 24 bit signed values
                        d = bytes(self.crsf_payload)
                        values = [int.from_bytes(d[1 + i * 3:4 + i * 3], 'big',
                                                 signed=True)
                                  for i in range((len(d) - 1) // 3)]
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'RPM source {}: {}'.format(
                                d[0], ', '.join(str(v) for v in values))
                        })
                    elif self.crsf_frame_type == 0x0D:  # Temperature
                        # source id, then one or more int16 in 0.1 degrees
                        d = bytes(self.crsf_payload)
                        values = [int.from_bytes(d[1 + i * 2:3 + i * 2], 'big',
                                                 signed=True) / 10
                                  for i in range((len(d) - 1) // 2)]
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': 'Temperature source {}: {}'.format(
                                d[0], ', '.join('{} C'.format(v) for v in values))
                        })
                    elif self.crsf_frame_type == 0x0E:  # Cells / voltage array
                        # source id below 128 means cell voltages, at or above
                        # means a voltage array. Values are uint16 millivolts.
                        d = bytes(self.crsf_payload)
                        values = [int.from_bytes(d[1 + i * 2:3 + i * 2], 'big') / 1000
                                  for i in range((len(d) - 1) // 2)]
                        label = 'Cells' if d[0] < 128 else 'Voltages'
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': '{} source {}: {}'.format(
                                label, d[0],
                                ', '.join('{} V'.format(v) for v in values))
                        })
                    elif self.crsf_frame_type == 0x1C:  # Link statistics Rx
                        d = bytes(self.crsf_payload)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': ('Downlink RSSI: -{} dB ,RSSI: {}% ,'
                                        'Link Quality: {}% ,SNR: {} dB ,'
                                        'Uplink power: {} dBm').format(
                                d[0], d[1], d[2],
                                self.unsigned_to_signed_8(d[3]), d[4])
                        })
                    elif self.crsf_frame_type == 0x1D:  # Link statistics Tx
                        d = bytes(self.crsf_payload)
                        payload_str = ('Uplink RSSI: -{} dB ,RSSI: {}% ,'
                                       'Link Quality: {}% ,SNR: {} dB ,'
                                       'Downlink power: {} dBm').format(
                            d[0], d[1], d[2],
                            self.unsigned_to_signed_8(d[3]), d[4])
                        if len(d) >= 6:
                            payload_str += ' ,Uplink rate: {} Hz'.format(d[5] * 10)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x17:  # Subset RC channels
                        # Configuration byte: bits 0-4 the first channel number,
                        # bits 5-6 the resolution, bit 7 reserved. The channel
                        # data follows, packed LSB first like 0x16, but scaled
                        # to microseconds with a 988 offset.
                        d = bytes(self.crsf_payload)
                        cfg = d[0]
                        first = (cfg & 0x1F) + 1
                        bits, scale = self.SUBSET_RC_RES[(cfg >> 5) & 0x03]
                        count = ((len(d) - 1) * 8) // bits
                        values = self.unpack_bits(d[1:], bits, count)
                        pairs = [(v, int(scale * v + 988)) for v in values]
                        payload_str = '[{}ch from CH{}, {} bit] '.format(
                            len(values), first, bits) + \
                            self.format_channel_values(pairs, first_channel=first)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x3A:  # Radio ID
                        # Extended header frame: destination, origin, sub type.
                        # Sub type 0x10 is the timing correction frame, holding
                        # a uint32 update interval and an int32 offset, both big
                        # endian and in 100ns units.
                        d = bytes(self.crsf_payload)
                        dest = self.CRSF_ADDRESSES_BY_INT.get(
                            d[0], format(d[0], '#x')) if len(d) > 0 else '?'
                        origin = self.CRSF_ADDRESSES_BY_INT.get(
                            d[1], format(d[1], '#x')) if len(d) > 1 else '?'
                        if len(d) >= 11 and d[2] == 0x10:
                            interval_us = int.from_bytes(
                                d[3:7], 'big', signed=True) / 10
                            offset_us = int.from_bytes(
                                d[7:11], 'big', signed=True) / 10
                            rate = 1000000 / interval_us if interval_us else 0
                            payload_str = (
                                'Sync: destination {} ,origin {} ,interval {} us'
                                ' ({} Hz) ,offset {} us').format(
                                    dest, origin, round(interval_us, 1),
                                    round(rate, 1), round(offset_us, 1))
                        else:
                            payload_str = 'Radio ID: destination {} ,origin {}'.format(
                                dest, origin)
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    elif self.crsf_frame_type == 0x16:  # RC channels packed
                        # 11 bits per channel, 16 channels per block (22 bytes).
                        # EdgeTX appends a status byte after the first block and,
                        # in 32 channel mode, a second block after that:
                        #   22          -> 16ch (plain CRSF)
                        #   22 + 1      -> 16ch + status (EdgeTX)
                        #   22 + 1 + 22 -> 32ch + status (EdgeTX extended 0x16)
                        data = self.crsf_payload
                        status = data[22] if len(data) >= 23 else None
                        channels = self.unpack_channels(data[0:22])
                        if len(data) >= 45:
                            channels += self.unpack_channels(data[23:45])

                        # 'RC' value converted to microseconds
                        pairs = [(v, int((v * 1024 / 1639) + 881))
                                 for v in channels]
                        payload_str = '[{}ch] '.format(
                            len(channels)) + self.format_channel_values(pairs)
                        status_str = self.describe_arming_status(status)
                        if status_str:
                            payload_str += ' | ' + status_str
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': payload_str
                        })
                    else:  # recognised type, no payload decoder yet
                        analyzerframe = AnalyzerFrame('crsf_payload', self.crsf_payload_start, self.crsf_payload_end, {
                            'payload': '{}: payload not decoded'.format(
                                self.frame_types.get(self.crsf_frame_type,
                                                     'Unknown')),
                            'error': ""})

                    return analyzerframe
                elif self.crsf_frame_current_index == (self.crsf_frame_length - 1):
                    # Last byte is actually the CRC.
                    analyzerframe = None
                    self.crsf_payload.append(payload)
                    #print('Payload complete ({}): {:2x}'.format(self.crsf_frame_current_index, payload))
                    # print(self.crsf_payload)
                    self.crsf_payload.insert(0, self.crsf_frame_type)
                    # convert type to bytes and then calcualtion CRC
                    crcresult = self.calCRC(packet=self.crsf_payload,
                                            bytes=len(self.crsf_payload))
                    if crcresult == 0:
                        crcresult = 'Pass'
                        error = ""
                    else:
                        crcresult = "Fail"
                        error = "CRC Fail"
                    analyzerframe = AnalyzerFrame('crsf_CRC', frame.start_time, frame.end_time, {
                        'crccheck': f"{crcresult}",
                        'error': f"{error}"
                    })

                    # And initialize again for next frame
                    self.crsf_new_packet_start = None
                    self.dec_fsm = self.dec_fsm_e.Idle
                    self.crsf_frame_length = 0
                    self.crsf_frame_type = None
                    self.crsf_frame_current_index = 0
                    self.crsf_payload = []
                    self.crsf_payload_start = None
                    self.crsf_payload_end = None
                    return analyzerframe
                else:
                    analyzerframe = AnalyzerFrame('crsf_error', frame.start_time, frame.end_time, {
                        'error': "Something Went Wrong"
                    })

                    # And initialize again for next frame
                    self.crsf_new_packet_start = None
                    self.dec_fsm = self.dec_fsm_e.Idle
                    self.crsf_frame_length = 0
                    self.crsf_frame_type = None
                    self.crsf_frame_current_index = 0
                    self.crsf_payload = []
                    self.crsf_payload_start = None
                    self.crsf_payload_end = None
                    return analyzerframe
        except Exception as e:
            print(f'error occured {e}')
            frame_start = self.crsf_frame_start
            frame_end = self.crsf_frame_end
            self.crsf_new_packet_start = None
            self.crsf_frame_end = None
            self.dec_fsm = self.dec_fsm_e.Idle
            self.crsf_frame_length = 0
            self.crsf_frame_type = None
            self.crsf_frame_current_index = 0
            self.crsf_payload = []
            self.crsf_payload_start = None
            self.crsf_payload_end = None
            analyzerframe = AnalyzerFrame('crsf_error', frame_start, frame_end, {
                'error': f"Program Error (Contact developer): type:{e.args}{e.with_traceback}"})
            return analyzerframe

    def calCRC(self, packet: list, bytes: int, gen_poly: int = 0xd5, start_from_byte=0):
        '''
        Calcualtes CRC value for the list provided to it.

        Returns: integer
        0 - CRC matched
        anything other than 0 - CRC match failed

        Parameters:
        packet : list of bytes on which CRC calculation needs to be done
        bytes : number of bytes on which CRC calculation needs to be done
        gen_poly(default = 0xd5) : Polynomial to use for calculating CRC
        start_from_byte(default = 0) : Start CRC calculation from which byte 

        Note: Slow for live Analysis.
        '''
        dividend = 0
        next_byte = 0
        number_of_bytes_processed = start_from_byte
        number_of_bits_left = 0
        is_MSB_one = False
        while(True):
            if number_of_bits_left <= 0 and number_of_bytes_processed - start_from_byte >= bytes:
                # ALL BITS PROCESSED
                break
            elif number_of_bits_left <= 0 and number_of_bytes_processed-start_from_byte < bytes:
                # load bits into buffer if empty and if bits available
                next_byte = packet[number_of_bytes_processed]
                number_of_bytes_processed = number_of_bytes_processed+1
                number_of_bits_left = 8
            is_MSB_one = dividend & 0b10000000
            # print(f"dividend = {bin(dividend)} , next_byte = {bin(next_byte)}")
            dividend = dividend << 1
            dividend = (dividend & 0b1011111111) | (next_byte >> 7)
            # shift First bit of Next_byte into dividend
            next_byte = (next_byte << 1)
            # because python doesnt allow to constarint size to 8
            next_byte = next_byte & 0b1011111111
            # Shift out the first bit
            number_of_bits_left = number_of_bits_left - 1
            if is_MSB_one == 0b10000000:
                dividend = (dividend ^ gen_poly)
            else:
                dividend = dividend
            # if bit aligning with MSB of gen_poly is 1 then do XOR

        return dividend
