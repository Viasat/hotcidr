import yaml
import ports

def load(f):
    r = yaml.safe_load(f)
    if r and 'rules' in r:
        for rule in r['rules']:
            if 'ports' in rule:
              p = ports.parse(rule['ports'])
              rule['ports'] = p
              rule['fromport'] = p.fromport
              rule['toport'] = p.toport
    return r

def dump(s, default_flow_style = True):
    if s and 'rules' in s:
        for rule in s['rules']:
            if 'ports' in rule:
                rule['ports'] = rule['ports'].yaml_str()
    return yaml.safe_dump(s, default_flow_style=default_flow_style)
