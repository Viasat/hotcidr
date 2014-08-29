import hotcidr.state

def get_params(config_yaml_file):
    f = open(config_yaml_file, 'r')
    y = hotcidr.state.load( f )
    f.close()
    return y

def write_params(config_yaml_file, config_yaml):
    f = open(config_yaml_file, 'w')
    f.write( hotcidr.state.dump( config_yaml, default_flow_style=False ) )
    f.close()

