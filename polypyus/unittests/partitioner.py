import unittest

from partionioner import (partition_addr_validator, partition_null_f,
                          slice_partitions)


class TestPartitioning(unittest.TestCase):
    def test_too_small(self):
        small = bytes([244] * 500)
        partitions = list(partition_null_f(small, border_treshold=1000))
        self.assertEqual(len(partitions), 1)
        self.assertEqual(partitions[0], slice(0, 500))

    def test_ends_with_0(self):
        ends_with_0 = bytes([244] * 2000 + [255] * 1000 + [1] * 3000 + [0] * 1000)
        partitions = list(partition_null_f(ends_with_0, border_treshold=1000))
        print(partitions)
        self.assertEqual(len(partitions), 2)
        self.assertEqual(partitions[0], slice(0, 2000))
        self.assertEqual(partitions[1], slice(3000, 6000))

    def test_start_with_0(self):
        starts_with_0 = bytes(
            [0] * 1001 + [244] * 2000 + [255] * 1000 + [1] * 3000 + [0] * 1000
        )
        partitions = list(partition_null_f(starts_with_0, border_treshold=1000))
        print(partitions)
        self.assertEqual(len(partitions), 2)
        self.assertEqual(partitions[0], slice(1001, 3001))
        self.assertEqual(partitions[1], slice(4001, 7001))


class TestAddrValidation(unittest.TestCase):
    def setUp(self):
        self.partitions = [slice(0, 1000), slice(2000, 4000), slice(3500, 6000)]
        self.tester = partition_addr_validator(self.partitions)

    def test_is_included(self):
        self.assertTrue(self.tester(500))
        self.assertTrue(self.tester(999))
        self.assertTrue(self.tester(0))
        self.assertTrue(self.tester(2000))
        self.assertTrue(self.tester(2500))
        self.assertTrue(self.tester(3500))
        self.assertTrue(self.tester(3999))
        self.assertTrue(self.tester(5500))
        self.assertTrue(self.tester(5900))
        self.assertTrue(self.tester(3500))

    def test_not_included(self):
        self.assertFalse(self.tester(1500))
        self.assertFalse(self.tester(1001))
        self.assertFalse(self.tester(1999))
        self.assertFalse(self.tester(1000))
        self.assertFalse(self.tester(-1000))
        self.assertFalse(self.tester(1500000))
