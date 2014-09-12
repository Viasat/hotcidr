import difflib
import inflect
import itertools
import logging
import netaddr
import os
import re
import toposort
import yaml
import hotcidr.state

def inflect_a(s, p=inflect.engine()):
    x = p.plural(s)
    if p.compare(s, x) == 'p:s':
        return s
    return p.a(s)

logging.basicConfig(format='%(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')

class Validator(object):
    logger = logging.getLogger('validation')
    info = logger.warn
    warn = logger.warn
    error = logger.error
    fatal = logger.fatal

    def load(self, x):
        if x not in self.files:
            try:
                with open(os.path.join(self.rootdir, x)) as f:
                    try:
                        self.files[x] = hotcidr.state.load(f)
                    except yaml.YAMLError:
                        self.fatal("Invalid YAML file %s" % x)
            except IOError:
                self.fatal("Could not read file %s" % x)
        return self.files[x]

    def register_check(self, f):
        if f not in self.checks:
            self.checks.append(f)
        else:
            raise Exception("Function %s is already registered" % f.__name__)

    def register_checks(self, *fs):
        for f in fs:
            self.register_check(f)

    required_map = {}
    def validate(self, wrap=True):
        # TODO: spawn multiple processes
        l = {f: Validator.required_map[f]
                 if f in Validator.required_map
                 else set()
                 for f in self.checks}
        for f in toposort.toposort_flatten(l, sort=False):
            if wrap:
                try:
                    f(self)
                except:
                    self.fatal("Unexpected exception raised by %s" %
                        f.__name__)
                    raise
            else:
                f(self)

    def __init__(self, rootdir):
        self.rootdir = rootdir
        self.checks = []
        self.files = {}


def has_rules(g):
    for i in g:
        if isinstance(i, tuple):
            if len(i) > 1 and 'rules' in i[1]:
                yield i
        elif 'rules' in i:
            yield i

def requires(*a):
    def decorator(f):
        Validator.required_map[f] = set(a)
        return f
    return decorator

def load_groups(self, forced=False):
    if forced or not hasattr(self, 'groups'):
        groupsdir = os.path.join(self.rootdir, 'groups')
        groups = os.listdir(groupsdir)
        self.groups = {}
        for x in groups:
            if os.path.isfile(os.path.join(groupsdir, x)):
                if x.endswith('.yaml'):
                    self.groups[x[:-5]] = self.load(os.path.join('groups', x))

def load_boxes(self, forced=False):
    if forced or not hasattr(self, 'boxes'):
      self.boxes = self.load('boxes.yaml')

@requires(load_groups, load_boxes)
def find_unused_groups(self):
    #TODO: include groups used in 'location' field
    used = set(itertools.chain(*(b['groups'] for b in self.boxes.values()
                                             if 'groups' in b)))
    for g in set(self.groups.keys()) - used:
        self.info("Group %s is unused" % g)

@requires(load_groups, load_boxes)
def validate_groups(self):
    used = set(itertools.chain(*(b['groups'] for b in self.boxes.values()
                                             if 'groups' in b)))
    valid_groups = set(self.groups.keys())
    for g in used - valid_groups:
        guess = difflib.get_close_matches(g, valid_groups)
        if guess:
            guess = " (Did you mean %s?)" % guess[0]
        else:
            guess = ""

        self.fatal("%s is not defined%s" % (g, guess))

@requires(load_groups)
def validate_group_names(self):
    valid_chars = set(
        'abcdefghijklmnopqrstuvwxyz'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        '0123456789'
        ' ._-:/()#,@[]+=&;{}!$*'
    )
    for name in self.groups.keys():
        if any(c not in valid_chars for c in name):
            self.fatal("%s is not a valid group name" % name)

@requires(load_boxes)
def validate_aws_instance_id(self):
    for name in self.boxes.keys():
        if not re.match(r'^i\-[0-9a-f]{8}$', name):
            self.fatal("Instance ID %s is not a valid AWS instance ID" % name)

@requires(load_groups)
def validate_aws_group_id(self):
    seen = {}
    for group_name, group in self.groups.items():
        if 'id' in group:
            name = group['id']
            if not re.match(r'^sg\-[0-9a-f]{8}$', name):
                self.fatal("%s has an invalid AWS group ID" % group_name)
            elif name in seen:
                if seen[name]:
                    self.fatal("%s has a duplicate AWS group ID" % seen[name])
                    seen[name] = False
                self.fatal("%s has a duplicate AWS group ID" % group_name)
            else:
                seen[name] = group_name

@requires(load_groups)
def validate_protocols(self):
    for group_name, group in has_rules(self.groups.iteritems()):
        for rule_num, rule in enumerate(group['rules'], 1):
            if 'protocol' not in rule:
                self.error("Rule %d in %s is missing a protocol" %
                    (rule_num, group_name))
            elif rule['protocol'] == '-1':
                self.error("Rule %d in %s has an invalid protocol" %
                    (rule_num, group_name))

@requires(load_groups)
def validate_ports(self):
    #TODO: handle ICMP fromport
    def port(x, default=-1):
        try:
            r = int(x)
            if 1 <= r <= 65535:
                return r
        except ValueError:
            pass
    for group_name, group in has_rules(self.groups.iteritems()):
        for rule_num, rule in enumerate(group['rules'], 1):
            valid = True

            if 'fromport' not in rule:
                self.error("Rule %d in %s is missing a fromport" %
                    (rule_num, group_name))
                valid = False

            if 'toport' not in rule:
                self.error("Rule %d in %s is missing a toport" %
                    (rule_num, group_name))
                valid = False

            if valid:
                fromport = port(rule['fromport'])
                toport = port(rule['toport'])
                valid = True
                if not fromport:
                    self.error("Rule %d in %s has an invalid fromport" %
                        (rule_num, group_name))
                    valid = False

                if not toport:
                    self.error("Rule %d in %s has an invalid toport" %
                        (rule_num, group_name))
                    valid = False

                if valid:
                    if fromport > toport:
                        self.error("Rule %d in %s has an invalid port range" %
                            (rule_num, group_name))
                    elif (toport - fromport) >= 100:
                        self.warn("Rule %d in %s has a large port range" %
                            (rule_num, group_name))

@requires(load_groups)
def validate_rule_fields(self):
    for group_name, group in has_rules(self.groups.iteritems()):
        for rule_num, rule in enumerate(group['rules'], 1):
            for field in ('description',):
                if field not in rule:
                    self.warn("Rule %d in %s is missing %s" %
                        (rule_num, group_name, inflect_a(field)))

@requires(load_groups)
def validate_group_fields(self):
    for group_name, group in self.groups.iteritems():
        for field in ('description', 'rules'):
            if field not in group:
                self.warn("%s is missing %s" % (group_name, inflect_a(field)))

@requires(load_boxes)
def validate_instance_fields(self):
    for box_id, box in self.boxes.iteritems():
        for field in ('ip', 'domain', 'groups'):
            if field not in box:
                self.warn("Box %s is missing %s" %
                    (box_id, inflect_a(field)))

@requires(load_groups)
def validate_locations(self):
    valid_groups = set(self.groups.keys())
    for group_name, group in has_rules(self.groups.iteritems()):
        for rule_num, rule in enumerate(group['rules'], 1):
            if 'location' in rule:
                if rule['location'] not in valid_groups:
                    try:
                        ip = netaddr.IPNetwork(rule['location'])
                        if str(ip.cidr) != rule['location']:
                            self.warn("Location for rule %d in %s "
                                      "will be interpreted as %s" %
                                (rule_num, group_name, ip.cidr))
                    except netaddr.AddrFormatError:
                        self.error("Rule %d in %s has an invalid location" %
                            (rule_num, group_name))
            else:
                self.error("Rule %d in %s is missing a location" %
                    (rule_num, group_name))
