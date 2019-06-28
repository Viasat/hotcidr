#!/usr/bin/python
import collections
import git
import itertools
import sys

from hotcidr import fetch
from hotcidr import util


class Action(object):
    def __call__(self, conn):
        try:
            self.run(conn)
        except:
            print("Unexpected exception raised. Aborting.")
            raise

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return tuple(self.__dict__.items()).__hash__()


class CreateSecurityGroup(Action):
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc

    def run(self, conn):
        conn.create_security_group(self.name, self.desc)

    def __repr__(self):
        return "Create new security group %s (%s)" % (self.name, self.desc)


class ModifyInstanceAttribute(Action):
    def __init__(self, inst_id, attr, value):
        self.inst_id = inst_id
        self.attr = attr
        self.value = value

    def run(self, conn):
        if self.attr == 'groupSet':
            self.value = map(lambda g: util.get_id_for_group(conn, g), self.value)
        conn.modify_instance_attribute(self.inst_id, self.attr, self.value)

    def __repr__(self):
        return "Set %s of %s to %s" % (self.attr, self.inst_id, self.value)


class ModifyRule(Action):
    def __init__(self, group, rule):
        self.group = group
        self.rule = rule

    def run(self, conn, f):
        loc = self.rule.location
        if loc == 'all':
            loc = '0.0.0.0/0'

        proto = self.rule.protocol
        if proto == 'all':
            proto = '-1'

        if self.rule.ports:
            fromport = self.rule.ports.fromport
            toport = self.rule.ports.toport
        else:
            fromport = -1
            toport = -1

        k = {
            'group_id': util.get_id_for_group(conn, self.group),
            'ip_protocol': proto,
            'from_port': fromport,
            'to_port': toport
        }
        if util.is_cidr(loc):
            f(cidr_ip=loc, **k)
        else:
            # Boto uses src_group_id or src_security_group_group_id to mean the
            # same thing depending on which function f is used here.
            loc = util.get_id_for_group(conn, loc)
            try:
                f(src_group_id=loc, **k)
            except TypeError:
                f(src_security_group_group_id=loc, **k)


class RemoveRule(ModifyRule):
    def run(self, conn):
        if self.rule.direction == 'inbound':
            f = conn.revoke_security_group
        elif self.rule.direction == 'outbound':
            f = conn.revoke_security_group_egress
        else:
            raise Exception("Invalid direction %s" % self.rule.direction)

        super(RemoveRule, self).run(conn, f)

    def __repr__(self):
        return "Del rule (%s, %s, %s) from %s" % (
                self.rule.protocol, self.rule.ports,
                self.rule.location, self.group)


class AddRule(ModifyRule):
    def run(self, conn):
        if self.rule.direction == 'inbound':
            f = conn.authorize_security_group
        elif self.rule.direction == 'outbound':
            f = conn.authorize_security_group_egress
        else:
            raise Exception("Invalid direction %s" % self.rule.direction)

        super(AddRule, self).run(conn, f)

    def __repr__(self):
        return "Add rule (%s, %s, %s) to %s" % (
                self.rule.protocol, self.rule.ports,
                self.rule.location, self.group)

rule_attr = ('direction', 'location', 'protocol', 'ports')
Rule = collections.namedtuple('Rule', rule_attr)


def rules(group):
    if 'rules' in group:
        for rule in group['rules']:
            r = {k: rule[k] for k in rule_attr if k in rule}
            for attr in rule_attr:
                r.setdefault(attr, None)
            yield Rule(**r)


def get_actions(old_dir, new_dir):
    old_instances = util.load_boxes(old_dir)
    old_groups = util.load_groups(old_dir)

    new_instances = util.load_boxes(new_dir)
    new_groups = util.load_groups(new_dir)

    # Add missing groups to AWS
    for g in new_groups:
        if g not in old_groups:
            if 'description' in new_groups[g]:
                desc = new_groups[g]['description']
            else:
                desc = "Automatically created by HotCIDR"
            yield CreateSecurityGroup(g, desc)

    # Update associated security groups for instances
    for old_id, old_inst in old_instances.items():
        if old_id in new_instances and 'groups' in new_instances[old_id]:
            groups = new_instances[old_id]['groups']
            if set(groups) != set(old_inst['groups']):
                yield ModifyInstanceAttribute(old_id, 'groupSet', groups)
        else:
            print("Skipping instance %s (Does not exist in AWS)" % old_id)

    # TODO: Delete security groups that are unused

    # Update rules for each security group
    for g, new_group in new_groups.items():
        new_rules = set(rules(new_group))

        if g in old_groups:
            old_rules = set(rules(old_groups[g]))
        else:
            old_rules = set()

        if new_rules != old_rules:
            for rule in old_rules - new_rules:
                yield RemoveRule(g, rule)
            for rule in new_rules - old_rules:
                yield AddRule(g, rule)


def changes(actions, unauthorized=0):
    objs = dict(zip([
        (CreateSecurityGroup, "%d group(s) created"),
        (ModifyInstanceAttribute, "%d instance(s) updated"),
        (AddRule, "%d rule(s) added"),
        (RemoveRule, "%d rule(s) removed"),
    ], itertools.repeat(0)))
    r = []
    for action in actions:
        for k in objs.iterkeys():
            if isinstance(action, k[0]):
                objs[k] += 1

    for k, v in objs.iteritems():
        out = k[1] % v
        x, _, y = out.partition('(s)')
        if v > 0:
            if v == 1:
                r.append(x + y)
            else:
                r.append(x + "s" + y)

    if unauthorized:
        if unauthorized == 1:
            r.append("1 unauthorized change found")
        else:
            r.append("%d unauthorized changes found" % unauthorized)

    if not r:
        return "No changes"
    return ", ".join(r)


def main(git_repo, region_code, vpc_id, aws_key, aws_secret, dry_run, expected_repo=None):
    with fetch.vpc(region_code, vpc_id, aws_key, aws_secret) as aws_dir, util.repo(git_repo) as git_dir:
        unauthorized_actions = []
        if expected_repo:
            try:
                with util.repo(git_repo, sha1=expected_repo) as exp_dir:
                    unauthorized_actions = list(get_actions(exp_dir, aws_dir))
                    for action in unauthorized_actions:
                        print("Unauthorized action: %s" % action)
            except git.exc.GitCommandError:
                print("Could not check for unauthorized changes.")
                print("Have you recently changed git repositories?")

        actions = list(get_actions(aws_dir, git_dir))

        conn = util.get_connection(vpc_id, region_code,
                aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        if not conn:
            print("Could not establish conection wtih AWS")
            sys.exit(1)

        count = len(actions)
        for num, action in enumerate(actions, 1):
            print("Action %d/%d: %s" % (num, count, action))
            sys.stdout.flush()
            if not dry_run:
                action(conn)

        print("hc-apply complete against %s" % util.get_hexsha(git_dir))
        print(changes(actions, unauthorized=len(unauthorized_actions)))
