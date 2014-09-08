#!/usr/bin/python
import os
import sys
import boto.ec2
import tempfile
import shutil

import hotcidr
from hotcidr import fetchvpc
from hotcidr import gitlib

class Action(object):
    def __call__(self):
        raise NotImplementedError


class CreateSecurityGroup(Action):
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc

    def __call__(self, conn):
        conn.create_security_group(self.name, self.desc)

    def __repr__(self):
        return "Create new security group %s (%s)" % (self.name, self.desc)


class ModifyInstanceAttribute(Action):
    def __init__(self, inst_id, attr, value):
        self.inst_id = inst_id
        self.attr = attr
        self.value = value

    def __call__(self, conn):
        conn.modify_instance_attribute(self.inst_id, self.attr, self.value)

    def __repr__(self):
        return "Set %s of %s to %s" % (self.attr, self.inst_id, self.value)


class ModifyRule(Action):
    def __init__(self, group, rule):
        self.group = group
        self.rule = rule

    def __call__(self, conn, f):
        proto = self.rule['protocol'] 
        if proto == 'all':
            proto = -1
        loc = self.rule['location']
        if loc == 'all':
            loc = '0.0.0.0/0'

        f(group_id=self.group,
          ip_protocol=proto,
          from_port=self.rule['ports'].fromport,
          to_port=self.rule['ports'].toport,
          cidr_ip=loc)


class RemoveRule(ModifyRule):
    def __call__(self, conn):
        if self.rule['direction'] == 'inbound':
            f = conn.revoke_security_group
        elif self.rule['direction'] == 'outbound':
            f = conn.revoke_security_group_egress
        else:
            raise Exception("Invalid direction %s" % self.rule['direction'])

        super(RemoveRule, self).__call__(conn, f)


    def __repr__(self):
        return "Remove rule (%s, %s, %s) from %s" % (
                self.rule['protocol'], self.rule['ports'],
                self.rule['location'], self.group)


class AddRule(ModifyRule):
    def __call__(self, conn):
        if self.rule['direction'] == 'inbound':
            f = conn.authorize_security_group
        elif self.rule['direction'] == 'outbound':
            f = conn.authorize_security_group_egress
        else:
            raise Exception("Invalid direction %s" % self.rule['direction'])

        super(AddRule, self).__call__(conn, f)

    def __repr__(self):
        return "Add rule (%s, %s, %s) to %s" % (
                self.rule['protocol'], self.rule['ports'],
                self.rule['location'], self.group)


class Rule(object):
    def __init__(self, **k):
        k.setdefault('description', None)
        k.setdefault('direction', None)
        k.setdefault('location', None)
        k.setdefault('protocol', None)
        k.setdefault('ports', hotcidr.ports.Port(-1))
        for i in k:
            setattr(self, i, k[i])

    def __hasitem__(self, k):
        return hasattr(self, k)

    def __getitem__(self, k):
        return getattr(self, k)

    def __setitem__(self, k, v):
        setattr(self, k, v)

    def __hash__(self):
        return tuple(self.__dict__.items()).__hash__()

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self.__dict__)


def rules(group):
    attr = ('direction', 'location', 'protocol', 'ports')
    if 'rules' in group:
        for rule in group['rules']:
            yield Rule(**{k: rule[k] for k in attr if k in rule})


def main(git_repo, region_code, aws_key, aws_secret):
    # Clone the git repo
    git_dir, successful = gitlib.get_valid_repo(git_repo)
    if not successful:
        sys.exit(1)

    # Fetch from AWS
    tmpdir = tempfile.mkdtemp()
    aws_dir = os.path.join(tmpdir, 'aws_out')
    fetchvpc.main(region_code,
                  aws_dir,
                  access_id=aws_key,
                  access_key=aws_secret,
                  silence=True)

    actions = list(get_actions(git_dir, aws_dir))

    gitlib.remove_git_repo()
    shutil.rmtree(tmpdir)

    conn = boto.ec2.connect_to_region(region_code,
                                      aws_access_key_id=aws_key,
                                      aws_secret_access_key=aws_secret)

    for action in actions:
        # TODO: Log changes somewhere?
        print(action)
        action(conn)


def get_actions(git_dir, aws_dir):
    aws_instances = gitlib.load_boxes(aws_dir)
    aws_groups = gitlib.load_groups(aws_dir)

    git_instances = gitlib.load_boxes(git_dir)
    git_groups = gitlib.load_groups(git_dir)

    # Add missing groups to AWS
    for g in git_groups:
        if g not in aws_groups:
            print("Adding group %s to AWS" % g)
            yield CreateSecurityGroup(g, 'no description')

    # Update associated security groups for instances
    for aws_id, aws_inst in aws_instances.items():
        if aws_id in git_instances and 'groups' in git_instances[aws_id]:
            groups = git_instances[aws_id]['groups']
            if set(groups) != set(aws_inst['groups']):
                groups = set(git_groups[g]['id'] for g in groups
                                                 if 'id' in git_groups[g])
                yield ModifyInstanceAttribute(aws_id, 'groupSet', groups)
        else:
            print("Skipping instance %s (Does not exist in AWS)" % aws_id)

    #TODO: Delete security groups that are unused

    # Update rules for each security group
    for group, git_group in git_groups.items():
        git_rules = set(rules(git_group))
        aws_rules = set(rules(aws_groups[group]))
        if git_rules != aws_rules:
            for rule in aws_rules - git_rules:
                yield RemoveRule(git_group['id'], rule)
            for rule in git_rules - aws_rules:
                yield AddRule(git_group['id'], rule)
