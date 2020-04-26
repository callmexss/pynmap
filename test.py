import pynmap
import unittest


class SimpleTest(unittest.TestCase):
    def test_scan(self, ip, port):
        ret = pynmap.scan(ip="127.0.0.1", port=80)
        self.assertTrue(ret)
        ret = pynmap.scan(ip="bing.com", port=80)
        self.assertFalse(ret)

        