#!/usr/bin/env/python2
import unittest
import hotcidr.validation as validation


class TestLogger(object):
    def __init__(self):
        self._mq = set()

    def expect_debug(self, msg):
        self._mq.add((msg, 'debug'))

    def expect_info(self, msg):
        self._mq.add((msg, 'info'))

    def expect_warn(self, msg):
        self._mq.add((msg, 'warn'))

    def expect_error(self, msg):
        self._mq.add((msg, 'error'))

    def expect_fatal(self, msg):
        self._mq.add((msg, 'fatal'))

    def debug(self, msg):
        try:
            m = (msg, 'debug')
            self.__test.assertIn(m, self._mq)
            self._mq.remove(m)
        except IndexError:
            self.__test.fail("Unexpected DEBUG %s" % msg)

    def info(self, msg):
        try:
            m = (msg, 'info')
            self.__test.assertIn(m, self._mq)
            self._mq.remove(m)
        except IndexError:
            self.__test.fail("Unexpected INFO %s" % msg)

    def warn(self, msg):
        try:
            m = (msg, 'warn')
            self.__test.assertIn(m, self._mq)
            self._mq.remove(m)
        except IndexError:
            self.__test.fail("Unexpected WARNING %s" % msg)

    def error(self, msg):
        try:
            m = (msg, 'error')
            self.__test.assertIn(m, self._mq)
            self._mq.remove(m)
        except IndexError:
            self.__test.fail("Unexpected ERROR %s" % msg)

    def fatal(self, msg):
        try:
            m = (msg, 'fatal')
            self.__test.assertIn(m, self._mq)
            self._mq.remove(m)
        except IndexError:
            self.__test.fail("Unexpected FATAL %s" % msg)

    def validate(self, test):
        self.__test = test
        validation.Validator.validate(self, wrap=False)
        self.__test.assertFalse(self._mq)


class Validator(TestLogger, validation.Validator):
    def __init__(self):
        TestLogger.__init__(self)
        self.checks = []

    def load(self, x):
        return self.files[x]


class TestCase(unittest.TestCase):
    def tearDown(self):
        self.v.validate(self)
        self.v = None


class TestFindUnusedGroups(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.find_unused_groups)

    def test_find_unused_groups(self):
        self.v.boxes = {}
        self.v.groups = {'unusedGroup': {}}
        self.v.expect_info("Group unusedGroup is unused")

    def test_all_groups_used(self):
        self.v.boxes = {
            'box1': {'groups': ['group1', 'group2']},
            'box2': {'groups': ['group1']},
            'box3': {'groups': ['group3']},
        }
        self.v.groups = {'group1': {}, 'group2': {}, 'group3': {}}


class TestValidateGroups(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_groups)

    def test_valid(self):
        self.v.boxes = {
            'box1': {'groups': ['group1', 'group2']},
            'box2': {'groups': ['group1']},
            'box3': {'groups': ['group3']},
        }
        self.v.groups = {'group1': {}, 'group2': {}, 'group3': {}}

    def test_undefined_group(self):
        self.v.boxes = {
            'box1': {'groups': ['dog', 'cat']},
            'box2': {'groups': ['bear']},
            'box3': {'groups': ['cat', 'bare']},
        }
        self.v.groups = {'bear': {}, 'dog': {}, 'cat': {}}
        self.v.expect_fatal("bare is not defined (Did you mean bear?)")


class TestValidateGroupNames(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_group_names)

    def test_valid(self):
        self.v.groups = {
            'group1': {},
            'group_2': {},
            'hotcidr': {},
        }

    def test_invalid(self):
        self.v.groups = {
            'nyan~~': {},
            '^_^': {},
            'actually valid :)': {}
        }
        self.v.expect_fatal("nyan~~ is not a valid group name")
        self.v.expect_fatal("^_^ is not a valid group name")


class TestValidateAWSInstanceID(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_aws_instance_id)

    def test_valid(self):
        self.v.boxes = {
            'i-aaaaaaaa': {},
            'i-bbbbbbbb': {},
            'i-cccccccc': {},
            'i-dddddddd': {}
        }

    def test_invalid(self):
        self.v.boxes = {
            'instance_1': {}
        }
        self.v.expect_fatal("Instance ID instance_1 is not a valid AWS instance ID")


class TestValidateAWSGroupID(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_aws_group_id)

    def test_valid(self):
        self.v.groups = {
            'group1': {
                'id': 'sg-12345678'
            },
            'group2': {
                'id': 'sg-23456789'
            }
        }

    def test_invalid(self):
        self.v.groups = {
            'group1': {
                'id': 'sg-34567890'
            },
            'group2': {
                'id': 'sg-34567890'
            }
        }
        self.v.expect_fatal("group1 has a duplicate AWS group ID")
        self.v.expect_fatal("group2 has a duplicate AWS group ID")


class TestValidateProtocols(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_protocols)

    def test_valid(self):
        self.v.groups = {
            'group1': {
                'rules': [
                    {'protocol': 'ICMP'},
                    {'protocol': 'TCP'}
                ]
            },
            'group2': {
                'rules': [
                    {'protocol': 'ICMP'},
                    {'protocol': 'UDP'}
                ]
            }
        }

    def test_invalid(self):
        self.v.groups = {
            'group1': {
                'rules': [
                    {}
                ]
            },
            'group2': {
                'rules': [
                    {'protocol': '-1'}
                ]
            }
        }
        self.v.expect_error("Rule 1 in group1 is missing a protocol")
        self.v.expect_error("Rule 1 in group2 has an invalid protocol")


class TestValidatePorts(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_ports)

    def test_valid(self):
        self.v.groups = {
            'group': {
                'rules': [
                    {
                        'fromport': '80',
                        'toport': '80'
                    },
                    {
                        'fromport': '2049',
                        'toport': '2049'
                    },
                    {
                        'fromport': '8000',
                        'toport': '8080'
                    }
                ]
            }
        }

    def test_missing_field(self):
        self.v.groups = {
            'group': {
                'rules': [
                    {
                        'fromport': '80',
                    },
                    {
                        'toport': '2049'
                    },
                    {
                    }
                ]
            }
        }
        self.v.expect_error("Rule 1 in group is missing a toport")
        self.v.expect_error("Rule 2 in group is missing a fromport")
        self.v.expect_error("Rule 3 in group is missing a toport")
        self.v.expect_error("Rule 3 in group is missing a fromport")

    def test_invalid_ports(self):
        self.v.groups = {
            'group': {
                'rules': [
                    {
                        'fromport': 'herp',
                        'toport': 'derp'
                    },
                    {
                        'fromport': '0',
                        'toport': '65536'
                    }
                ]
            }
        }
        self.v.expect_error("Rule 1 in group has an invalid fromport")
        self.v.expect_error("Rule 1 in group has an invalid toport")
        self.v.expect_error("Rule 2 in group has an invalid fromport")
        self.v.expect_error("Rule 2 in group has an invalid toport")

    def test_swapped_ports(self):
        self.v.groups = {
            'group': {
                'rules': [
                    {
                        'fromport': '8080',
                        'toport': '8000'
                    }
                ]
            }
        }
        self.v.expect_error("Rule 1 in group has an invalid port range")

    def test_large_port_range(self):
        self.v.groups = {
            'group': {
                'rules': [
                    {
                        'fromport': '6881',
                        'toport': '6999'
                    }
                ]
            }
        }
        self.v.expect_warn("Rule 1 in group has a large port range")


class TestValidateRuleFields(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_rule_fields)

    def test_valid(self):
        self.v.groups = {
            'group1': {
                'rules': [
                    {
                        'description': 'Test rule',
                        'justification': 'Needed for unit tests'
                    },
                ]
            }
        }

    def test_invalid(self):
        self.v.groups = {
            'group1': {
                'rules': [
                    {
                        'description': 'Test rule',
                    },
                    {
                        'justification': 'Needed for unit tests'
                    },
                    {
                    }
                ]
            }
        }
        self.v.expect_warn("Rule 2 in group1 is missing a description")
        self.v.expect_warn("Rule 3 in group1 is missing a description")


class TestValidateGroupFields(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_group_fields)

    def test_valid(self):
        self.v.groups = {
            'group1': {
                'description': 'Sample group 1',
                'id': 'sg-567890ab',
                'rules': []
            },
            'group2': {
                'description': 'Sample group 2',
                'id': 'sg-67890abc',
                'rules': []
            }
        }

    def test_invalid(self):
        self.v.groups = {
            'group1': {
                'description': 'Sample group 1'
            },
            'group2': {
                'rules': []
            },
            'group3': {}
        }
        self.v.expect_warn('group1 is missing rules')
        self.v.expect_warn('group2 is missing a description')
        self.v.expect_warn('group3 is missing a description')
        self.v.expect_warn('group3 is missing rules')


class TestValidateInstanceFields(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_instance_fields)

    def test_valid(self):
        self.v.boxes = {
            'i-eeeeeeee': {
                'ip': '10.8.0.1',
                'domain': 'hotcidr-1.example.com',
                'groups': []
            },
            'i-ffffffff': {
                'ip': '10.8.0.2',
                'domain': 'hotcidr-2.example.com',
                'groups': []
            },
            'i-11111111': {
                'ip': '10.8.0.3',
                'domain': 'hotcidr-3.example.com',
                'groups': []
            }
        }

    def test_invalid(self):
        self.v.boxes = {
            'i-22222222': {
                'domain': 'hotcidr-1.example.com',
                'groups': []
            },
            'i-33333333': {
                'ip': '10.8.0.2',
            },
            'i-44444444': {
            }
        }
        self.v.expect_warn("Box i-22222222 is missing an ip")
        self.v.expect_warn("Box i-33333333 is missing a domain")
        self.v.expect_warn("Box i-33333333 is missing groups")
        self.v.expect_warn("Box i-44444444 is missing an ip")
        self.v.expect_warn("Box i-44444444 is missing a domain")
        self.v.expect_warn("Box i-44444444 is missing groups")


class TestValidateLocations(TestCase):
    def setUp(self):
        self.v = Validator()
        self.v.register_check(validation.validate_locations)

    def test_valid(self):
        self.v.groups = {
            'a': {'id': 'sg-55555555'},
            'b': {
                'rules': [
                    {'location': 'a'},
                    {'location': '0.0.0.0/0'},
                    {'location': '10.8.0.1/32'},
                ]
            }
        }

    def test_invalid(self):
        self.v.groups = {
            'a': {},
            'b': {
                'rules': [
                    {'location': 'd'},
                    {'location': '192.168.1.1/24'},
                    {'location': '8.8.8.8/0'},
                ]
            }
        }
        self.v.expect_error("Rule 1 in b has invalid location 'd'")
        self.v.expect_warn("Location for rule 2 in b will be interpreted as 192.168.1.0/24")
        self.v.expect_warn("Location for rule 3 in b will be interpreted as 0.0.0.0/0")


if __name__ == '__main__':
    unittest.main()
