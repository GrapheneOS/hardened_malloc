import os
import subprocess
import unittest


class TestSimpleMemoryCorruption(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.dir = os.path.dirname(os.path.realpath(__file__))

    def run_test(self, test_name):
        sub = subprocess.Popen(self.dir + "/" + test_name,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        return stdout, stderr, sub.returncode

    def test_delete_type_size_mismatch(self):
        _stdout, stderr, returncode = self.run_test(
            "delete_type_size_mismatch")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: sized deallocation mismatch (small)\n")

    def test_double_free_large_delayed(self):
        _stdout, stderr, returncode = self.run_test(
            "double_free_large_delayed")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_double_free_large(self):
        _stdout, stderr, returncode = self.run_test("double_free_large")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_double_free_small_delayed(self):
        _stdout, stderr, returncode = self.run_test(
            "double_free_small_delayed")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: double free (quarantine)\n")

    def test_double_free_small(self):
        _stdout, stderr, returncode = self.run_test("double_free_small")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: double free (quarantine)\n")

    def test_eight_byte_overflow_large(self):
        _stdout, _stderr, returncode = self.run_test(
            "eight_byte_overflow_large")
        self.assertEqual(returncode, 0)

    def test_eight_byte_overflow_small(self):
        _stdout, stderr, returncode = self.run_test(
            "eight_byte_overflow_small")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: canary corrupted\n")

    def test_invalid_free_protected(self):
        _stdout, stderr, returncode = self.run_test("invalid_free_protected")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_invalid_free_small_region_far(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_free_small_region_far")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: invalid free within a slab yet to be used\n")

    def test_invalid_free_small_region(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_free_small_region")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: double free\n")

    def test_invalid_free_unprotected(self):
        _stdout, stderr, returncode = self.run_test("invalid_free_unprotected")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_read_after_free_large(self):
        _stdout, _stderr, returncode = self.run_test("read_after_free_large")
        self.assertEqual(abs(returncode), 11)

    def test_read_after_free_small(self):
        stdout, _stderr, returncode = self.run_test("read_after_free_small")
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.decode("utf-8"),
                         "0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n")

    def test_read_zero_size(self):
        _stdout, _stderr, returncode = self.run_test("read_zero_size")
        self.assertEqual(abs(returncode), 11)

    def test_string_overflow(self):
        stdout, _stderr, returncode = self.run_test("string_overflow")
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.decode("utf-8"), "overflow by 0 bytes\n")

    def test_unaligned_free_large(self):
        _stdout, stderr, returncode = self.run_test("unaligned_free_large")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_unaligned_free_small(self):
        _stdout, stderr, returncode = self.run_test("unaligned_free_small")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid unaligned free\n")

    def test_uninitialized_free(self):
        _stdout, stderr, returncode = self.run_test("uninitialized_free")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_uninitialized_malloc_usable_size(self):
        _stdout, _stderr, returncode = self.run_test(
            "uninitialized_malloc_usable_size")
        self.assertEqual(abs(returncode), 11)

    def test_uninitialized_realloc(self):
        _stdout, stderr, returncode = self.run_test("uninitialized_realloc")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid realloc\n")

    def test_write_after_free_large_reuse(self):
        _stdout, _stderr, returncode = self.run_test(
            "write_after_free_large_reuse")
        self.assertEqual(abs(returncode), 11)

    def test_write_after_free_large(self):
        _stdout, _stderr, returncode = self.run_test("write_after_free_large")
        self.assertEqual(abs(returncode), 11)

    def test_write_after_free_small_reuse(self):
        _stdout, stderr, returncode = self.run_test(
            "write_after_free_small_reuse")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: detected write after free\n")

    def test_write_after_free_small(self):
        _stdout, stderr, returncode = self.run_test("write_after_free_small")
        self.assertEqual(abs(returncode), 6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: detected write after free\n")

    def test_write_zero_size(self):
        _stdout, _stderr, returncode = self.run_test("write_zero_size")
        self.assertEqual(abs(returncode), 11)


if __name__ == '__main__':
    unittest.main()
