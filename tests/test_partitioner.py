import unittest

from polypyus.partionioner import partition_null_f


class TestPartitioning(unittest.TestCase):
    def test_too_small(self):
        small = bytes([244] * 500)
        partitions = list(partition_null_f(small, border_treshold=1000))
        self.assertEqual(len(partitions), 1)
        self.assertEqual(partitions[0], slice(0, 500))

    def test_ends_with_0(self):
        ends_with_0 = bytes([244] * 2000 + [255] * 1000 + [1] * 3000 + [0] * 1000)
        partitions = list(partition_null_f(ends_with_0, border_treshold=1000))
        self.assertEqual(len(partitions), 2)
        self.assertEqual(partitions[0], slice(0, 2000))
        self.assertEqual(partitions[1], slice(3000, 6000))

    def test_start_with_0(self):
        starts_with_0 = bytes(
            [0] * 1001 + [244] * 2000 + [255] * 1000 + [1] * 3000 + [0] * 1000
        )
        partitions = list(partition_null_f(starts_with_0, border_treshold=1000))
        self.assertEqual(len(partitions), 2)
        self.assertEqual(partitions[0], slice(1001, 3001))
        self.assertEqual(partitions[1], slice(4001, 7001))
