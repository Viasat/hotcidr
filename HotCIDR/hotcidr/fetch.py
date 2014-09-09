from __future__ import print_function
from hotcidr import util
from hotcidr import ports
from hotcidr import state
import boto.ec2
import contextlib
import os.path
import shutil
import sys
import tempfile
import yaml

def dump(x):
    return state.dump(x, default_flow_style=False)

def append_to_rules(rules, group, rule, grant, inout_str):
    srcip_str = None

    if hasattr(grant, 'cidr_ip'):
        if grant.cidr_ip:
            srcip_str = str(grant.cidr_ip)

    if not srcip_str:
        srcip_str = group.name

    none_string = 'None'

    if rule.ip_protocol == '-1':
        ip_protocol_str = 'all'
    else:
        ip_protocol_str = none_string if rule.ip_protocol == None else rule.ip_protocol.encode('utf-8')

    if not rule.from_port or not rule.to_port:
        rules.append(dict([
            ('description',none_string if group.description == None else group.description.encode('utf-8')),
            ('direction',inout_str),
            ('protocol',ip_protocol_str),
            ('location',srcip_str),
            ]))

    else:
        rules.append(dict([
            ('description',none_string if group.description == None else group.description.encode('utf-8')),
            ('direction',inout_str),
            ('protocol',ip_protocol_str),
            ('location',srcip_str),
            ('ports', ports.Port(int(rule.from_port), int(rule.to_port)) ),
            ]))

def main(vpc_region_code, output = '', access_id = None, access_key = None, silence = None):

    args = {}
    args['output'] = output
    args['silence'] = silence
    args['access_id'] = access_id
    args['access_key'] = access_key

    #Check argument validity
    if not util.is_valid_vpc(vpc_region_code):
        print('Error: invalid vpc-region-code.', file=sys.stderr)
        return 1

    yaml.add_representer(dict, yaml.representer.SafeRepresenter.represent_dict)

    #Setup directory structure
    outdir = args['output']
    relgroupsdir = 'groups'
    groupsdir = os.path.join(outdir, relgroupsdir)
    try:
        os.mkdir(outdir)
    except:
        shutil.rmtree(outdir)
        os.mkdir(outdir)
        #print('Please remove the directory ' + outdir + ' before continuing')
        #return 1

    try:
        os.mkdir(groupsdir)
    except Exception:
        print('Please remove the directory ' + groupsdir + ' before continuing')
        return 1

    try:
        if not args['access_id'] or not args['access_key']:
            connection = boto.ec2.connect_to_region(vpc_region_code)
        else:
            connection = boto.ec2.connect_to_region(vpc_region_code, aws_access_key_id=args['access_id'], aws_secret_access_key=args['access_key'])
    except boto.exception.NoAuthHandlerFound:
        print('Error: boto credentials are invalid. Check your configuration.')
        return 1

    groups = connection.get_all_security_groups()

    for group in groups:
        if not args['silence']:
            print('Forming group %s' % str(group.id))
        fn = os.path.join(outdir, relgroupsdir, '%s.yaml' % str(group.name))

        rules = []
        data = {
            'id': group.id.encode('utf-8'),
            'description': group.description.encode('utf-8'),
            'rules': rules
        }

        #Inbound rules
        for rule in group.rules:
            for grant in rule.grants:
                append_to_rules(rules, group, rule, grant, 'inbound')

        #Outbound rules
        for rule in group.rules_egress:
            for grant in rule.grants:
                append_to_rules(rules, group, rule, grant, 'outbound')

        with open(fn, 'w') as out:
            out.write(dump(data))

    instances = connection.get_only_instances()

    instancesDict = dict()
    for instance in instances:
        if not args['silence']:
            print('Found instance %s' % instance)

        k = instance.id.encode('utf-8')

        try:
            ip = instance.ip_address or '' #instance.private_ip_address
            domain = instance.public_dns_name or '' #instance.private_dns_name
            v = {
                'ip': ip.encode('utf-8'),
                'domain': domain.encode('utf-8'),
                'tags': {k.encode('utf-8'): v.encode('utf-8') for k, v in instance.tags.items()},
                'groups': [str(group.name) for group in instance.groups]
            }
            instancesDict[k] = v
        except Exception:
            print("ERROR: Could not process instance %s" % instance)
    with open(os.path.join(outdir, 'boxes.yaml'), 'w') as out:
        out.write(dump(instancesDict))

    open(os.path.join(outdir, 'expirations.yaml'), 'w')

@contextlib.contextmanager
def vpc(region, key, secret):
    tmpdir = tempfile.mkdtemp()
    main(region, tmpdir, key, secret, True)
    yield tmpdir
    shutil.rmtree(tmpdir)
