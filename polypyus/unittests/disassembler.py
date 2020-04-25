import unittest

from disassembler import Function, sweep, sweep_function


class TestFunctionSweep(unittest.TestCase):
    def setUp(self):
        self.start = 0x58008
        self.end = 0x5807C
        self.target_blocks = [
            (0x58008, 0x58024),
            (0x58024, 0x5802A),
            (0x5802A, 0x5806C),
            (0x5806C, 0x5807C),
        ]
        with open("./20735B1.bin", "rb") as f:
            self.data = f.read()

    def test_find_all(self):
        function_blocks = sweep_function(self.data, self.start, set())
        fnc = Function(function_blocks)
        print(fnc)
        # bound = parts.bound()
        # print(f"bound: 0x{bound.start:X} - 0x{bound.stop:X}")
        self.assertEqual(4, len(fnc.function_blocks))
        for block in fnc.function_blocks:
            bound = (block.start_addr, block.stop_addr)
            self.assertIn(bound, self.target_blocks)
