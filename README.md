# CRSF Frame Parser

Saleae Logic 2 High Level Analyzer: Crossfire decoder for the R/C protocol as used by
TBS Crossfire, Tracer, ExpressLRS and EdgeTX radios.

## Getting started 🛠️

1. Install the analyzer in Logic 2. The marketplace build (1.0.1 at the time of
   writing) predates 32 channel support, so to run this version clone the repo and use
   *Extensions → Load Existing Extension…*, pointing it at `extension.json`.
2. Create a new 'Async Serial' analyzer, set the baud rate to match the link, 8N1, LSB,
   non-inverted.
3. Create a new 'CRSF Frame Parser' analyzer, configure it and pick the previously
   created 'Async Serial' analyzer.
4. Done. 🚀

Baud rate is 420000 on TBS Crossfire. EdgeTX defaults to 400000 and can be set to
115200, 400000, 921600, 1870000, 3750000 or 5250000.

![Decode link statistics frame](images/decode_link_statistics.png)
![Decode RC channels packed frame](images/decode_rc_channels_packed.png)

## Features ✨

Full decoding of:

* RC channels packed (0x16), both 16 and 32 channel frames
* Subset RC channels packed (0x17), all four resolutions
* Link statistics (0x14)
* Battery sensor (0x08)
* Flight mode (0x21)
* GPS (0x02)
* Heart beat (0x0B)
* Ping (0x28)
* Attitude (0x1E)
* Device info (0x29)
* Radio ID (0x3A), including the timing sync sub frame
* Vario (0x07)
* Baro altitude (0x09), both encodings, with TBS or ELRS vario when present
* GPS time (0x03)
* Airspeed (0x0A)
* RPM (0x0C)
* Temperature (0x0D)
* Cells and voltage array (0x0E)
* Link statistics Rx (0x1C) and Tx (0x1D)

The standalone sync type (0x10) is recognised but not decoded; in practice the sync is
carried inside a Radio ID (0x3A) frame, which is decoded. The remaining 11 named types
are the parameter protocol (0x2A to 0x2D, 0x32) and the KISS, MSP and ArduPilot
passthrough frames; they are reported by name with the payload left undecoded and no
error flagged.

Field layouts and scaling follow EdgeTX's own parser in
`radio/src/telemetry/crossfire.cpp`, and every decoder has a test built from values
checked against it.

It also provides:

* CRC check
* Destination device address
* Selectable channel value units: `us`, `Digital Value` or `Both`
* Payload length check per frame type
* Basic error handling

The decoder is a state machine that parses every frame, so it is straightforward to
extend to further frame types. Some groundwork for additional frames already exists.

## RC channels, 16 and 32 🎛️

EdgeTX appends a status byte after the first channel block and, in 32 channel mode, a
second block after that. The status byte therefore sits *between* the two blocks:

| Payload length | Contents                                     |
| -------------- | -------------------------------------------- |
| 22             | 16 channels, plain CRSF                      |
| 22 + 1         | 16 channels + EdgeTX status byte             |
| 22 + 1 + 22    | 32 channels + status byte (extended 0x16)    |

The status byte carries the ELRS arming extension: bit 0 is the commanded arm state in
Switch mode, bit 1 flags CH5 arming mode.

Decoded output is prefixed with `[16ch]` or `[32ch]` and the arming mode is appended, so
a 32 channel frame is obvious at a glance.

## Tests 🧪

```
python3 tests/test_crsf_hla.py
```

The harness stubs the Saleae SDK, so the decoder can be exercised offline without Logic.
It covers 16 and 32 channel frames, the status byte, CRC pass and fail, unit selection
and back to back frames.

## Changelog 📋

### 1.4.0

* Decode subset RC channels packed (0x17) at 10, 11, 12 and 13 bit resolution,
  honouring the starting channel number. The type was previously unknown, and an
  unknown type resets the decoder mid frame, which could manufacture bogus frames from
  the bytes that followed

### 1.3.0

* Decode the telemetry sensors: vario, baro altitude, GPS time, airspeed, RPM,
  temperature, cells and voltage array, and link statistics Rx and Tx
* Link statistics reported uplink TX power as the raw table index, so an index of 3
  displayed as 3 mW where it means 100 mW

### 1.2.0

* Decode Radio ID (0x3A), the frame that carries the ELRS/EdgeTX timing sync: update
  interval, resulting rate and offset. These were previously reported as a decode error
* GPS, attitude and heart beat were read little endian; CRSF telemetry is big endian, so
  every one of those fields was byte swapped
* A recognised frame type with no decoder is no longer reported as an error

### 1.1.0

* Support for 32 channel RC frames and decoding of the EdgeTX status byte
* Channel values are labelled in microseconds; they were previously labelled `ms`
* Fixed 16 and 32 bit sign conversion, which broke every negative value
* Fixed GPS latitude, longitude, ground speed and heading scaling
* Fixed attitude, which multiplied by 10000 instead of dividing
* Fixed heart beat and ping device lookups, which reported every device as unknown
* Fixed device info, which raised a TypeError on every frame
* Removed debug prints, including one inside the CRC inner loop
* Added GPS time, airspeed, RPM, temperature and cells to the frame type table
* Added an offline test harness

## ToDo ☝️

* Decode the OpenTX/EdgeTX sync (0x10) payload
* Decode more of the telemetry frames that are currently only recognised by name
* Extended header frames (0x28 to 0x96) are only partly handled

## Credits 🙏

Original analyzer by Max Gröning, further work by Ansh Chawla. Licensed under Apache-2.0.
