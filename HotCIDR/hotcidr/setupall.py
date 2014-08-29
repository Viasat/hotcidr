from __future__ import print_function
import sys

import config
import gitlib

def main(config_yaml_file):
    params = config.get_params(config_yaml_file)

    expected_repo_fields = ['aws_access_key_id','aws_secret_access_key','vpc_region','git_api_url','git_api_token','git_repo_name']

    for repo_name in params['repos']:
        repo_params = params['repos'][repo_name]
        print('Processing: ' + repo_name, file=sys.stderr)

        fields_exist = True
        for field in expected_repo_fields:
            if not field in repo_params:
                print('ERROR: repo ' + repo_name + ' is missing the ' + field + ' parameter, and it is necessary for setup. Repo will be skipped.', file=sys.stderr)
                fields_exist = False

        if not fields_exist:
            continue

        repo_params['git_repo_url'] = gitlib.create_remote_repo(repo_params['git_api_url'], repo_params['vpc_region'], repo_params['git_repo_name'], repo_params['git_api_token'])
        gitlib.commit_fetch(repo_params['git_repo_url'], repo_params['vpc_region'], repo_params['aws_access_key_id'], repo_params['aws_secret_access_key'])

    config.write_params(config_yaml_file, params)

