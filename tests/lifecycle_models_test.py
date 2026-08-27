import unittest
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

try:
    from tools.lifecycle_models import AttachmentManager, ConcealRanges
except ImportError:
    AttachmentManager = None
    ConcealRanges = None


class ConcealRangesTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(ConcealRanges, "lifecycle_models is not implemented")
        self.ranges = ConcealRanges(page_size=0x1000, maximum_ranges=4)

    def test_normalizes_overlap_adjacency_and_insertion_order(self):
        self.assertTrue(self.ranges.add_physical(0x5000, 0x1000))
        self.assertTrue(self.ranges.add_physical(0x1003, 0x1FFD))
        self.assertTrue(self.ranges.add_physical(0x3000, 0x2000))
        self.assertEqual(self.ranges.snapshot(), [(0x1000, 0x5000)])
        self.assertTrue(self.ranges.contains(0x1000))
        self.assertTrue(self.ranges.contains(0x5FFF))
        self.assertFalse(self.ranges.contains(0x6000))

    def test_rejects_overflow_and_capacity_without_partial_change(self):
        self.assertFalse(self.ranges.add_physical((1 << 64) - 0x800, 0x1000))
        self.assertEqual(self.ranges.snapshot(), [])
        for page in (0x1000, 0x3000, 0x5000, 0x7000):
            self.assertTrue(self.ranges.add_physical(page, 0x1000))
        before = self.ranges.snapshot()
        self.assertFalse(self.ranges.add_physical(0x9000, 0x1000))
        self.assertEqual(self.ranges.snapshot(), before)

    def test_virtual_registration_is_transactional(self):
        translations = {0x1000: 0xA000, 0x2000: 0, 0x3000: 0xC000}
        self.assertFalse(
            self.ranges.add_virtual(0x1800, 0x1800, translations.get)
        )
        self.assertEqual(self.ranges.snapshot(), [])

    def test_publication_rejects_late_registration(self):
        self.assertTrue(self.ranges.add_physical(0x1000, 0x1000))
        generation, snapshot = self.ranges.publish()
        self.assertGreater(generation, 0)
        self.assertEqual(snapshot, [(0x1000, 0x1000)])
        self.assertFalse(self.ranges.add_physical(0x3000, 0x1000))


class AttachmentManagerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(AttachmentManager, "lifecycle_models is not implemented")
        self.manager = AttachmentManager()

    def request(self, mode="probe", nonce=(1, 2), reserved=0):
        return {
            "size": 48,
            "version": 1,
            "header_bytes": 48,
            "mode": mode,
            "flags": 0xC,
            "required": 1,
            "optional": 2,
            "nonce": nonce,
            "reserved": reserved,
        }

    def test_probe_only_reaches_eligible_without_ownership(self):
        result = self.manager.execute(self.request(), available=3)
        self.assertEqual(result["state"], "eligible")
        self.assertEqual(result["failure"], "none")
        self.assertEqual(result["ownership"], 0)

    def test_unsupported_data_plane_fails_before_prepare(self):
        result = self.manager.execute(self.request(mode="root"), available=3)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["failure"], "provider-unavailable")
        self.assertEqual(result["ownership"], 0)

    def test_invalid_abi_and_zero_nonce_fail_closed(self):
        bad = self.request(nonce=(0, 0))
        self.assertEqual(self.manager.execute(bad, 3)["failure"], "abi-mismatch")
        bad = self.request()
        bad["reserved"] = 1
        self.assertEqual(self.manager.execute(bad, 3)["failure"], "abi-mismatch")

    def test_rollback_is_reverse_order_and_idempotent(self):
        released = []
        ownership = 0b101101
        ownership = self.manager.rollback(
            ownership, lambda bit: released.append(bit)
        )
        self.assertEqual(ownership, 0)
        self.assertEqual(released, [5, 3, 2, 0])
        self.assertEqual(self.manager.rollback(ownership, released.append), 0)
        self.assertEqual(released, [5, 3, 2, 0])


if __name__ == "__main__":
    unittest.main()