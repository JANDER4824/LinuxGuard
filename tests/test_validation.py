import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from LinuxGuard import validate_ip, validate_port

class TestValidation(unittest.TestCase):
    def test_validate_ip_valid(self):
        self.assertTrue(validate_ip('192.168.1.1'))
        self.assertTrue(validate_ip('0.0.0.0'))
        self.assertTrue(validate_ip('255.255.255.255'))

    def test_validate_ip_with_cidr(self):
        self.assertTrue(validate_ip('192.168.0.0/24'))
        self.assertTrue(validate_ip('10.0.0.0/8'))

    def test_validate_ip_invalid_format(self):
        self.assertFalse(validate_ip('999.999.999.999'))
        self.assertFalse(validate_ip('256.256.256.256'))
        self.assertFalse(validate_ip('1.2.3'))
        self.assertFalse(validate_ip('abc.def.ghi.jkl'))
        self.assertFalse(validate_ip('1234.0.0.1'))
        self.assertFalse(validate_ip('192.168.0.0/33'))
        self.assertFalse(validate_ip('192.168.0.0/abc'))

    def test_validate_port_valid(self):
        for port in [1, 22, 80, 65535]:
            with self.subTest(port=port):
                self.assertTrue(validate_port(port))

    def test_validate_port_invalid(self):
        for port in [0, -1, 65536, 'abc', '']: 
            with self.subTest(port=port):
                self.assertFalse(validate_port(port))

if __name__ == '__main__':
    unittest.main()
