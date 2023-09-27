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
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: sized deallocation mismatch (small)\n")

    def test_double_free_large_delayed(self):
        _stdout, stderr, returncode = self.run_test(
            "double_free_large_delayed")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_double_free_large(self):
        _stdout, stderr, returncode = self.run_test("double_free_large")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_double_free_small_delayed(self):
        _stdout, stderr, returncode = self.run_test(
            "double_free_small_delayed")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: double free (quarantine)\n")

    def test_double_free_small(self):
        _stdout, stderr, returncode = self.run_test("double_free_small")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: double free (quarantine)\n")

    def test_overflow_large_1_byte(self):
        _stdout, _stderr, returncode = self.run_test(
            "overflow_large_1_byte")
        self.assertEqual(returncode, -11)

    def test_overflow_large_8_byte(self):
        _stdout, _stderr, returncode = self.run_test(
            "overflow_large_8_byte")
        self.assertEqual(returncode, -11)

    def test_overflow_small_1_byte(self):
        _stdout, stderr, returncode = self.run_test(
            "overflow_small_1_byte")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: canary corrupted\n")

    def test_overflow_small_8_byte(self):
        _stdout, stderr, returncode = self.run_test(
            "overflow_small_8_byte")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: canary corrupted\n")

    def test_invalid_free_protected(self):
        _stdout, stderr, returncode = self.run_test("invalid_free_protected")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_invalid_free_small_region_far(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_free_small_region_far")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: invalid free within a slab yet to be used\n")

    def test_invalid_free_small_region(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_free_small_region")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: double free\n")

    def test_invalid_free_unprotected(self):
        _stdout, stderr, returncode = self.run_test("invalid_free_unprotected")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_invalid_malloc_usable_size_small_quarantene(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_malloc_usable_size_small_quarantine")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: invalid malloc_usable_size (quarantine)\n")

    def test_invalid_malloc_usable_size_small(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_malloc_usable_size_small")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: invalid malloc_usable_size\n")

    def test_read_after_free_large(self):
        _stdout, _stderr, returncode = self.run_test("read_after_free_large")
        self.assertEqual(returncode, -11)

    def test_read_after_free_small(self):
        stdout, _stderr, returncode = self.run_test("read_after_free_small")
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.decode("utf-8"),
                         "0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n0\n")

    def test_read_zero_size(self):
        _stdout, _stderr, returncode = self.run_test("read_zero_size")
        self.assertEqual(returncode, -11)

    def test_string_overflow(self):
        stdout, _stderr, returncode = self.run_test("string_overflow")
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.decode("utf-8"), "overflow by 0 bytes\n")

    def test_unaligned_free_large(self):
        _stdout, stderr, returncode = self.run_test("unaligned_free_large")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_unaligned_free_small(self):
        _stdout, stderr, returncode = self.run_test("unaligned_free_small")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid unaligned free\n")

    def test_unaligned_malloc_usable_size_small(self):
        _stdout, stderr, returncode = self.run_test(
            "unaligned_malloc_usable_size_small")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid unaligned malloc_usable_size\n")

    def test_uninitialized_free(self):
        _stdout, stderr, returncode = self.run_test("uninitialized_free")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid free\n")

    def test_uninitialized_malloc_usable_size(self):
        _stdout, stderr, returncode = self.run_test(
            "uninitialized_malloc_usable_size")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid malloc_usable_size\n")

    def test_uninitialized_realloc(self):
        _stdout, stderr, returncode = self.run_test("uninitialized_realloc")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: invalid realloc\n")

    def test_write_after_free_large_reuse(self):
        _stdout, _stderr, returncode = self.run_test(
            "write_after_free_large_reuse")
        self.assertEqual(returncode, -11)

    def test_write_after_free_large(self):
        _stdout, _stderr, returncode = self.run_test("write_after_free_large")
        self.assertEqual(returncode, -11)

    def test_write_after_free_small_reuse(self):
        _stdout, stderr, returncode = self.run_test(
            "write_after_free_small_reuse")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: detected write after free\n")

    def test_write_after_free_small(self):
        _stdout, stderr, returncode = self.run_test("write_after_free_small")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode("utf-8"),
                         "fatal allocator error: detected write after free\n")

    def test_write_zero_size(self):
        _stdout, _stderr, returncode = self.run_test("write_zero_size")
        self.assertEqual(returncode, -11)

    def test_malloc_object_size(self):
        _stdout, _stderr, returncode = self.run_test("malloc_object_size")
        self.assertEqual(returncode, 0)

    def test_malloc_object_size_offset(self):
        _stdout, _stderr, returncode = self.run_test(
            "malloc_object_size_offset")
        self.assertEqual(returncode, 0)

    def test_invalid_malloc_object_size_small(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_malloc_object_size_small")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: invalid malloc_object_size\n")

    def test_invalid_malloc_object_size_small_quarantine(self):
        _stdout, stderr, returncode = self.run_test(
            "invalid_malloc_object_size_small_quarantine")
        self.assertEqual(returncode, -6)
        self.assertEqual(stderr.decode(
            "utf-8"), "fatal allocator error: invalid malloc_object_size (quarantine)\n")

    def test_impossibly_large_malloc(self):
        _stdout, stderr, returncode = self.run_test(
            "impossibly_large_malloc")
        self.assertEqual(returncode, 0)

    def test_uninitialized_read_small(self):
        _stdout, stderr, returncode = self.run_test(
            "uninitialized_read_small")
        self.assertEqual(returncode, 0)

    def test_uninitialized_read_large(self):
        _stdout, stderr, returncode = self.run_test(
            "uninitialized_read_large")
        self.assertEqual(returncode, 0)

    def test_realloc_init(self):
        _stdout, _stderr, returncode = self.run_test(
            "realloc_init")
        self.assertEqual(returncode, 0)

if __name__ == '__main__':
    unittest.main()
