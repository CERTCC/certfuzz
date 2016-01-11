'''
Created on Apr 8, 2011

@organization: cert.org
'''
import os
import tempfile
import hashlib
from certfuzz.debuggers.output_parsers.gdbfile import GDBfile
from certfuzz.debuggers.output_parsers.debugger_file_base import registers
import unittest

class _Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        (fd, f) = tempfile.mkstemp(text=True)
        # write three lines to the temp file
        os.write(fd, "\n".join(("abc", "def", "ghi")))
        os.write(fd, '\n')
        os.close(fd)

        self.file = f

    def tearDown(self):
        self.delete_file(self.file)

    def test_read_gdb(self):
        gdb = GDBfile(self.file)
        lines = gdb.lines

        # make sure all three lines were returned
        self.assertEqual(len(lines), 3)
        for s in ("abc", "def", "ghi"):
            self.assertTrue(s in lines)

    def test_is_crash(self):
        fd = open(self.file, 'a')
        fd.write("SIGKILL\n")
        fd.close()

        g = GDBfile(self.file)
        self.assertFalse(g.is_crash)

        # overwrite the file...
        fd = open(self.file, 'w')
        fd.write("SIGHUP\n")
        fd.close()

        g = GDBfile(self.file)
        self.assertFalse(g.is_crash)

        # overwrite the file...
        fd = open(self.file, 'w')
        fd.write("Program exited normally\n")
        fd.close()

        g = GDBfile(self.file)
        self.assertFalse(g.is_crash)

    def test_is_corrupt_stack(self):
        g = GDBfile(self.file)
        g._look_for_corrupt_stack('foo bar')
        self.assertFalse(g.is_corrupt_stack)
        g._look_for_corrupt_stack('corrupt stack')
        self.assertTrue(g.is_corrupt_stack)

    def test_is_assert_fail(self):
        g = GDBfile(self.file)
        self.assertFalse(g.is_assert_fail)

        fd = open(self.file, 'a')
        fd.write("\n__assert_fail\n")
        fd.close()

        g = GDBfile(self.file)
        # it's not good enough to just have an assert fail string
        # anywhere in the input file
        self.assertFalse(g.is_assert_fail)

        # it has to be in the backtrace for it to count
        # as a real assertion failure for our purposes
        g.backtrace.append('__assert_fail')
        g._look_for_assert_fail()
        self.assertTrue(g.is_assert_fail)

    def test_is_debugbuild(self):
        g = GDBfile(self.file)
        self.assertFalse(g.is_debugbuild)

        fd = open(self.file, 'a')
        fd.write("Darmok and Jalad at Tanagra\n")
        fd.close()

        g = GDBfile(self.file)
        self.assertTrue(g.is_debugbuild)

    def test_hashable_backtrace_string(self):
        gdbf = GDBfile(self.file)
        self.assertFalse(gdbf._hashable_backtrace())

        gdbf.lines.append('#0 0x11111111 in ??')
        gdbf.lines.append('#1 0x22222222 in foo at foo.c:80')
        gdbf.lines.append('#2 0x33333333 in bar')

        gdbf._process_lines()
        gdbf._hashable_backtrace()
        self.assertEqual(gdbf._hashable_backtrace_string(1), '0x11111111')
        self.assertEqual(gdbf._hashable_backtrace_string(2), '0x11111111 foo.c:80')
        self.assertEqual(gdbf._hashable_backtrace_string(3), '0x11111111 foo.c:80 0x33333333')

    def test_get_crash_signature(self):
        gdbf = GDBfile(self.file)
        self.assertFalse(gdbf._hashable_backtrace())

        gdbf.lines.append('#0 0x11111111 in ??')
        gdbf.lines.append('#1 0x22222222 in foo at foo.c:80')
        gdbf.lines.append('#2 0x33333333 in bar')

        gdbf._process_lines()
        gdbf._hashable_backtrace()
        self.assertEqual(gdbf.get_crash_signature(1), hashlib.md5('0x11111111').hexdigest())
        self.assertEqual(gdbf.get_crash_signature(2), hashlib.md5('0x11111111 foo.c:80').hexdigest())
        self.assertEqual(gdbf.get_crash_signature(3), hashlib.md5('0x11111111 foo.c:80 0x33333333').hexdigest())

    def test_backtrace(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.write(fd, "#0 A\n")
        os.write(fd, "#1 B\n")
        os.write(fd, " from bar\n")
        os.write(fd, " at foo\n")
        os.write(fd, "C\n")
        os.write(fd, "#3 D\n")
        os.write(fd, "  X from baz\n")
        os.write(fd, "  N at qux\n")
        # this one should NOT show up because in the event
        # of a corrupt stack we drop the last backtrace line
        os.write(fd, "#4 E at blah\n")
        os.write(fd, "(corrupt stack?)\n")
        os.close(fd)

        gdbf = GDBfile(f)
        self.assertEqual(gdbf.backtrace, ["A", "B from bar at foo", "D X from baz N at qux"])

        self.delete_file(f)

    def test_registers(self):
        gdbf = GDBfile(self.file)
        self.assertFalse(gdbf.registers)

        for r in registers:
            gdbf.lines.append('%s\t0xf00\tbar' % r)

        gdbf._process_lines()

        for r in registers:
            self.assertEqual(gdbf.registers_hex[r], '0xf00')
            self.assertEqual(gdbf.registers[r], 'bar')

        # TODO: finish writing this test

    def test_backtrace_without_questionmarks(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.write(fd, "#0 A\n")
        os.write(fd, "#1 ?? B\n")
        os.write(fd, "C\n")
        os.write(fd, "#2 D at foo\n")
        os.close(fd)

        gdbf = GDBfile(f)
        gdbf._backtrace_without_questionmarks()
        self.assertEqual(gdbf.backtrace_without_questionmarks, ["A", "D at foo"])

        self.delete_file(f)

    def test_hashable_backtrace(self):
        gdbf = GDBfile(self.file)
        self.assertFalse(gdbf._hashable_backtrace())

        gdbf.lines.append('#0 0x11111111 in ??')
        gdbf.lines.append('#1 0x22222222 in foo at foo.c:80')
        gdbf.lines.append('#2 0x33333333 in bar')

        gdbf._process_lines()
        self.assertEqual(gdbf._hashable_backtrace(), ['0x11111111', 'foo.c:80', '0x33333333'])

    def test_received_signal(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.write(fd, "#0 A\n")
        os.write(fd, "#1 ?? B\n")
        os.write(fd, "C\n")
        os.write(fd, "#2 D at foo\n")
        os.write(fd, "Program received signal WINNING, Charlie Sheen fault.\n")
        os.close(fd)

        gdbf = GDBfile(f)
        self.assertEqual(gdbf.signal, "WINNING")

        self.delete_file(f)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
