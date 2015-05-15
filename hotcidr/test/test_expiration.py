import os
import time
import unittest
from shutil import rmtree, copytree
import git
import yaml
import tempfile

import hotcidr.fetch
import hotcidr.deleteexpired

test_repo_name = 'repo_test'
test_repo_src = os.path.join(os.path.realpath(__file__).rsplit('/', 1)[0], test_repo_name)
seconds_to_wait = 5


class TestExpiration(unittest.TestCase):

    def test_rulesyaml_expiration(self):
        # Create new repo from repo_test
        temp_path = tempfile.mkdtemp()
        test_repo_path = os.path.join(temp_path, test_repo_name)
        copytree(test_repo_src, test_repo_path)

        # Initially commit repo
        git.Git(test_repo_path).init()
        git.Git(test_repo_path).config('user.name', '"Test User"')
        git.Git(test_repo_path).config('user.email', '"test@example.com"')
        git.Git(test_repo_path).add('*')
        git.Git(test_repo_path).commit('-m', 'Initial commit')

        # Test files
        test_file_name = 'groups/test1.yaml'
        test_file_path = os.path.join(test_repo_path, test_file_name)

        # Make the actual expiration change and commit it
        test_file = open(test_file_path, 'r')
        yaml_file = yaml.load(test_file)
        test_file.close()

        yaml_file['rules'][0]['expiration'] = seconds_to_wait
        yaml_file['rules'][1]['expiration'] = 2*seconds_to_wait

        test_file = open(test_file_path, 'w')
        test_file.write(yaml.dump(yaml_file, default_flow_style=False))
        test_file.close()

        git.Git(test_repo_path).add(test_file_name)
        git.Git(test_repo_path).commit('-m', 'Added rule expirations')

        # Get the file before rule expiration, assert 2 rules exist
        #   deleteexpired should do nothing since the rule hasn't expired yet
        start_time = time.time()
        hotcidr.deleteexpired.main(test_repo_path, dont_push=True, silence=False)

        test_file = open(test_file_path, 'r')
        yaml_pre = yaml.load(test_file)
        test_file.close()
        self.assertEqual(len(yaml_pre['rules']), 2)

        # Wait 2 total seconds for the rule to expire, then delete it
        time_to_wait = seconds_to_wait*3/2  # Allow some buffer time for deleteexpire to run
        if time.time() - start_time < time_to_wait:
            sleeptime = time_to_wait - (time.time() - start_time)
        else:
            sleeptime = 0
        time.sleep(sleeptime)

        hotcidr.deleteexpired.main(test_repo_path, dont_push=True, silence=False)
        start_time = time.time()

        # Get the file after rule expiration, assert 1 rule exists
        test_file = open(test_file_path, 'r')
        yaml_post = yaml.load(test_file)
        test_file.close()
        self.assertEqual(len(yaml_post['rules']), 1)

        # Wait 4 total seconds for the rule to expire, then delete it
        time_to_wait = 2*seconds_to_wait*2  # Allow some buffer time for deleteexpire to run
        if time.time() - start_time < time_to_wait:
            sleeptime = time_to_wait - (time.time() - start_time)
        else:
            sleeptime = 0
        time.sleep(sleeptime)
        hotcidr.deleteexpired.main(test_repo_path, dont_push=True, silence=False)

        # Get the file after rule expiration, assert that no more rules remain
        test_file = open(test_file_path, 'r')
        yaml_none = yaml.load(test_file)
        test_file.close()
        self.assertEqual(len(yaml_none['rules']), 0)

        # Clean up temp directory
        rmtree(temp_path)

    def test_expirationyaml(self):
        # Create new repo from repo_test
        temp_path = tempfile.mkdtemp()
        test_repo_path = os.path.join(temp_path, test_repo_name)
        copytree(test_repo_src, test_repo_path)

        # Initially commit repo
        git.Git(test_repo_path).init()
        git.Git(test_repo_path).config('user.name', '"Test User"')
        git.Git(test_repo_path).config('user.email', '"test@example.com"')
        git.Git(test_repo_path).add('*')
        git.Git(test_repo_path).commit('-m', 'Initial commit')

        # Test files
        test_file_name = 'groups/test1.yaml'
        test_file_path = os.path.join(test_repo_path, test_file_name)
        expirations_file_path = os.path.join(test_repo_path, 'expirations.yaml')

        # Make the actual expiration change and commit it
        test_file = open(expirations_file_path, 'w')

        test_file_yaml = yaml.dump(
            {'rules': [
                {
                    'location': '192.168.0.2/32',
                    'ports': 443,
                    'expiration': seconds_to_wait
                }, {
                    'location': '192.168.0.3/32',
                    'ports': 443,
                    'expiration': 2*seconds_to_wait
                }
            ]},
            default_flow_style=False)

        test_file.write(test_file_yaml)
        test_file.close()

        git.Git(test_repo_path).add(expirations_file_path)
        git.Git(test_repo_path).commit('-m', '\'Added rule expirations\'')

        # Get current time
        start_time = time.time()

        # Get the file before rule expiration, assert 2 rules exist
        #   deleteexpired should do nothing since the rule hasn't expired yet
        hotcidr.deleteexpired.main(test_repo_path, dont_push=True, silence=False)
        test_file = open(test_file_path, 'r')
        yaml_pre = yaml.load(test_file)
        test_file.close()
        self.assertEqual(len(yaml_pre['rules']), 2)

        # Wait 2 total seconds for the rule to expire, then delete it
        time_to_wait = seconds_to_wait*3/2  # Allow some buffer time for deleteexpire to run
        if time.time() - start_time < time_to_wait:
            sleeptime = time_to_wait - (time.time() - start_time)
        else:
            sleeptime = 0
        time.sleep(sleeptime)
        hotcidr.deleteexpired.main(test_repo_path, dont_push=True, silence=False)

        # Get the file after rule expiration, assert 1 rule exists
        test_file = open(test_file_path, 'r')
        yaml_post = yaml.load(test_file)
        test_file.close()
        self.assertEqual(len(yaml_post['rules']), 1)

        # Wait 4 total seconds for last rule to expire, then delete it
        time_to_wait = 2*seconds_to_wait*2  # Allow some buffer time for deleteexpire to run
        if time.time() - start_time < time_to_wait:
            sleeptime = time_to_wait - (time.time() - start_time)
        else:
            sleeptime = 0
        time.sleep(sleeptime)
        hotcidr.deleteexpired.main(test_repo_path, dont_push=True, silence=False)

        # Get the file after rule expiration, assert that no more rules remain
        test_file = open(test_file_path, 'r')
        yaml_none = yaml.load(test_file)
        test_file.close()
        self.assertEqual(len(yaml_none['rules']), 0)

        # Clean up temp directory
        rmtree(temp_path)

if __name__ == '__main__':
    unittest.main()
