"""Guard against unbootable ESP32-C3 images and changes to partition shape."""
import importlib.util
import pathlib
import struct
import unittest

spec = importlib.util.spec_from_file_location(
    'guard', pathlib.Path(__file__).resolve().parents[1] / 'scripts/check_firmware_layout.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def partitions(app_size=0x140000, *, app_offset=0x10000):
    records = [
        (1, 2, 0x9000, 0x5000, 'nvs'),
        (1, 0, 0xE000, 0x2000, 'otadata'),
        (0, 0x10, app_offset, app_size, 'app0'),
        (0, 0x11, 0x150000, 0x140000, 'app1'),
        (1, 0x82, 0x290000, 0x160000, 'spiffs'),
    ]
    return b''.join(
        struct.pack('<HBBII16sI', 0x50AA, typ, subtype, off, size,
                    name.encode().ljust(16, b'\0'), 0)
        for typ, subtype, off, size, name in records
    ) + b'\xff' * 32


class FirmwarePartitionGuardTests(unittest.TestCase):
    def test_optimized_image_passes(self):
        guard.check(b'\0' * 1271136, partitions())

    def test_previous_unbootable_image_rejected(self):
        with self.assertRaisesRegex(guard.LayoutError, 'APP_OVERSIZE'):
            guard.check(b'\0' * 1321904, partitions())

    def test_safety_margin_required(self):
        with self.assertRaisesRegex(guard.LayoutError, 'APP_OVERSIZE'):
            guard.check(b'\0' * (0x140000 - 100), partitions())

    def test_wrong_app_offset_rejected(self):
        with self.assertRaisesRegex(guard.LayoutError, 'app partition'):
            guard.check(b'\0' * 12345, partitions(app_offset=0x20000))

    def test_overlapping_partitions_rejected(self):
        with self.assertRaisesRegex(guard.LayoutError, 'overlap'):
            guard.check(b'\0' * 12345, partitions(app_size=0x150000))

    def test_invalid_partition_table_rejected(self):
        with self.assertRaisesRegex(guard.LayoutError, 'magic'):
            guard.check(b'\0' * 12345, b'AB' + partitions()[2:])
