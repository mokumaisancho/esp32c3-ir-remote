#!/usr/bin/env python3
"""Reject firmware that exceeds its ESP-IDF app partition or safety margin."""
import argparse
import pathlib
import struct

ENTRY = struct.Struct('<HBBII16sI')
MAGIC = 0x50AA
APP_OFFSET = 0x10000
MIN_HEADROOM = 16 * 1024


class LayoutError(ValueError):
    pass


def parse_partitions(data):
    partitions = []
    for cursor in range(0, len(data) - ENTRY.size + 1, ENTRY.size):
        magic, ptype, subtype, offset, size, name, flags = ENTRY.unpack_from(data, cursor)
        if magic in (0xFFFF, 0xEBEB):
            break
        if magic != MAGIC:
            raise LayoutError(f'invalid partition magic at {cursor:#x}: {magic:#x}')
        if size == 0:
            raise LayoutError('zero-sized partition')
        partitions.append(dict(type=ptype, subtype=subtype, offset=offset,
                               size=size, name=name.split(b'\0', 1)[0].decode('ascii', 'replace')))
    if not partitions:
        raise LayoutError('partition table has no valid entries')
    return partitions


def check(firmware, partitions_blob, *, firmware_offset=APP_OFFSET,
          min_headroom=MIN_HEADROOM):
    entries = parse_partitions(partitions_blob)
    matches = [p for p in entries if p['type'] == 0 and p['offset'] == firmware_offset]
    if len(matches) != 1:
        raise LayoutError(f'exactly one app partition at {firmware_offset:#x} required, found {len(matches)}')
    app = matches[0]
    if app['subtype'] != 0x10:
        raise LayoutError(f'app offset points to unexpected subtype {app["subtype"]:#x}; expected ota_0')
    flashlen = len(firmware)
    if flashlen == 0:
        raise LayoutError('firmware image is empty')
    headroom = app['size'] - flashlen
    if headroom < min_headroom:
        raise LayoutError(f'APP_OVERSIZE_OR_MARGIN: image={flashlen} partition={app["size"]} '
                          f'headroom={headroom} required_headroom={min_headroom}')
    ordered = sorted(entries, key=lambda p: p['offset'])
    for before, after in zip(ordered, ordered[1:]):
        if before['offset'] + before['size'] > after['offset']:
            raise LayoutError(f'overlap: {before["name"]} and {after["name"]}')
    print(f'APP_IMAGE_BYTES={flashlen} OTA_PARTITION_BYTES={app["size"]} '
          f'HEADROOM={headroom} REQUIRED_HEADROOM={min_headroom} RESULT=PASS')
    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('firmware', type=pathlib.Path)
    parser.add_argument('partitions', type=pathlib.Path)
    parser.add_argument('--min-headroom', type=int, default=MIN_HEADROOM)
    args = parser.parse_args()
    try:
        check(args.firmware.read_bytes(), args.partitions.read_bytes(),
              min_headroom=args.min_headroom)
    except (OSError, LayoutError) as exc:
        parser.exit(2, f'BLOCKED: {exc}\n')


if __name__ == '__main__':
    main()
