from __future__ import print_function
from shutil import rmtree
from hotcidr import state
import boto.ec2
import boto.vpc
import contextlib
import datetime
import git
import hashlib
import json
import os
import requests
import shutil
import sys
import tempfile
import time
import yaml

#This function is different than isinstance(n,int) in that it will pass for strings: e.g. '1'
def isint(n):
    try:
        int(n)
        return True
    except:
        return False

#socket.inet_aton(addr) is not used here since EC2 addresses cannot be integers - they must be "x:x:x:x/x"
def is_cidr(s):
    if hasattr(s, 'split'):
        n = s.split('.',4)
        if isint(n[0]) and isint(n[1]) and isint(n[2]):
            n3 = n[3].split('/',1)
            if isint(n3[0]) and (len(n3) == 1 or isint(n3[1])):
                return True
    return False    

#Check if valid vpc string
def is_valid_vpc(vpc):
    valid_regions = set([
        'ap-northeast-1',
        'ap-southeast-1',
        'ap-southeast-2',
        'eu-west-1',
        'sa-east-1',
        'us-east-1',
        'us-west-1',
        'us-west-2'])

    return vpc in valid_regions

rule_fields = ['direction','protocol','location']

#Load boxes
def load_boxes(d):
    return state.load(open(os.path.join(d, 'boxes.yaml')))

#Get the security group id(s) based on a security group name
def get_sgid(conn, sgname, vpc_id):
    ids = list()
    for sg in conn.get_all_security_groups(filters={'group-name':sgname, 'vpc-id':vpc_id}):
        ids.append(sg.id)
    return ids

#Get the security group id(s) based on a security group name
def get_sgname(conn, sgid, vpc_id):
    return conn.get_all_security_groups(filters={'group-id':sgid, 'vpc-id':vpc_id})[0].name

#Load groups
def load_groups(d, ext='.yaml'):
    groups_dir = os.path.join(d, 'groups')
    assert(os.path.isdir(groups_dir))
    r = {}
    for group in os.listdir(groups_dir):
        if group.endswith(ext):
            f = os.path.join(groups_dir, group)
            group_name = group[:-len(ext)]
            r[group_name] = state.load(open(f))
    return r

#Get a hash string from a rule
def get_hash_from_rule(rule_orig):
    rule = rule_orig.copy()

    for field in rule_fields:
        if field not in rule:
            rule[field] = ''

    if not 'justification' in rule:
        justification = ''
    else:
        justification = rule['justification']

    if not 'expiration' in rule:
        expiration = ''
    else:
        expiration = rule['expiration']

    if 'ports' in rule:
        identifier = (str(rule['direction'])
                    + str(rule['protocol'])
                    + str(rule['location'])
                    + str(rule['ports'])
                    + str(justification)
                    + str(expiration)
                      )
    else:
        identifier = (str(rule['direction'])
                    + str(rule['protocol'])
                    + str(rule['location'])
                    + str(justification)
                    + str(expiration)
                      )

    hash = hashlib.md5()
    hash.update(identifier)
    return str(hash.digest())

#Given the repo path, return a dict of the groups
def get_groups_dict(repo_path):
    groups_dict = {}
    for dirname,dirnames,filenames in os.walk(os.path.join(repo_path,'groups')):
        for filename in filenames:
            if filename.endswith('.yaml'):
                groups_dict[filename.rsplit('.',1)[0]] = 'groups/' + filename
    return groups_dict

#git_api_url: Api url for git, e.g. 'api.github.com', 'git.viasat.com/api/v3'
#repo_name: Desired repo name for the new repo, e.g. 'us-west-2-core'
#vpc: The vpc region code, e.g. 'us-west-2'
#auth: The personal access token. Created in git: Account Settings/Applications/Personal Access Tokens
def create_remote_repo(git_api_url, vpc, repo_name, auth):
    if not is_valid_vpc(vpc):
        print('ERROR: Remote repo could not be created: ' + vpc + ' is not a valid vpc-region-code.')
        return None

    auth_header = {'Authorization': 'token ' + auth}
    try:
        repo_user = json.loads(requests.get(git_api_url + 'user', headers=auth_header).content)['login'] 
    except ValueError:
        print('ERROR: ' + git_api_url + ' did not respond. URL is invalid or inaccessible.')
        return None
    
    #Get list of repos
    repos = {}
    repos_response_url = json.loads(requests.get(git_api_url + 'user', headers=auth_header).content)['repos_url']
    repos_response = json.loads(requests.get(repos_response_url, headers=auth_header).content)
    for r in repos_response:
        repos[ r['name'].encode('utf-8') ] = r['ssh_url'].encode('utf-8')

    #Prompt user to delete repo if it exists already
    if repo_name in repos.keys():
        desired_repo_url = repos[repo_name]
        var = raw_input('Warning: ' + desired_repo_url + ' already exists. Delete it? (y/n) ')
    else:
        var ='n'

    #Delete repo if it exists
    if var == 'y':
        r = requests.delete(git_api_url + 'repos/' + repo_user + '/' + repo_name, headers=auth_header)
        print('Deleted ' + desired_repo_url)

        #After the delete request is successful, we must wait for it to be processed.
        #Ideally we would probe the repo, but it says 'repo not found' even before it has been deleted entirely
        #Additionally, the status code is successful even when the request hasn't been processed yet
        #Thus I wait 5 seconds, which is usually enough time
        print('Waiting 5 seconds for delete request to be processed')
        time.sleep(5)

    #Create repo
    r = requests.post(git_api_url + 'user/repos', json.dumps({'name':repo_name}), headers=auth_header)

    #Get list of repos
    repos = {}
    repos_response_url = json.loads(requests.get(git_api_url + 'user', headers=auth_header).content)['repos_url']
    repos_response = json.loads(requests.get(repos_response_url, headers=auth_header).content)
    for r in repos_response:
        repos[ r['name'].encode('utf-8') ] = r['ssh_url'].encode('utf-8')

    if repo_name in repos.keys():
        desired_repo_url = repos[repo_name]
    else:
        desired_repo_url = ''

    print('Added ' + desired_repo_url) 

    return desired_repo_url

#Check for git repo existence: create directory if it is a repo, else load directory normally
def get_valid_repo( repo ):

    if repo == None:
        print('ERROR: git repo is specified as \"None\". Please enter in a valid repo or clone url.',file=sys.stderr)
        return None, None

    #If the repo is not a directory
    if not os.path.isdir(repo):
        is_git_repo = True

        if not repo.endswith('.git'):
            print('Error: ' + repo + ' is not a directory nor a valid git clone URL.', file=sys.stderr)
            return None, None

        try:
            git.Git().ls_remote( repo )
        except:
            print('Error: ' + repo + ' is not a valid git clone URL.', file=sys.stderr)

        #Get new repo location
        gitrepo_location = tempfile.mkdtemp()
        new_repo_path = os.path.join(gitrepo_location, repo.rsplit('/',1)[1].rsplit('.',1)[0])
        new_full_path = os.path.join(gitrepo_location, new_repo_path)

        if os.path.exists(new_full_path):
            rmtree(new_full_path)
        git.Repo.clone_from(repo, new_full_path)

        repo = new_repo_path

    #If the repo is a directory, check that it is a git repo
    else:
        is_git_repo = False

        try:
            git.Git( repo ).status()
        except:
            print('ERROR: ' + repo + ' is not a valid git repo. Try \'git init\' in that directory before continuing.',file=sys.stderr)
            return None, None

        try:
            git.Git( repo ).log()
        except:
            print('ERROR: ' + repo + ' has no commits. Commit before continuing.',file=sys.stderr)
            return None, None

        try:
            git.Git( repo ).pull()
        except:
            #print('Warning: ' + repo + ' could not be pulled - no remote exists?',file=sys.stderr)
            pass

    return repo, is_git_repo

def get_init_commit(git_dir, yamlfile):
    init_commit = git.Git( git_dir ).log('--format="%an;%at;%H"', yamlfile).split('\n')[-1][1:-1].rsplit(';',2)
    init_commit[2] = init_commit[2].rsplit('\n',1)[0]
    return init_commit

def get_git_commit(hexsha, git_dir, yamlfile):
    init_commit = get_init_commit(git_dir, yamlfile)
    if init_commit[2] == hexsha:
        commit_message = git.Git( git_dir ).log(hexsha, '--format=\"%B\"').replace('\n', ' ')[1:-1].rstrip()
        return commit_message
    else:
        commit_message = git.Git( git_dir ).log('--ancestry-path', hexsha + '^..' + hexsha, '--format=\"%B\"').replace('\n', ' ')[1:-1].rstrip()
        return commit_message

def get_commit_approved_authdate(commit_hexsha, git_dir, yamlfile):
    #If the commit is the initial git commit, return the initial commit author/date
    #This is needed since the next Git command run will check <commit_hexsha>^, the parent, which won't exist if the commit is the initial one.
    init_commit = get_init_commit(git_dir, yamlfile)

    if commit_hexsha == init_commit[2]:
        return {'author':init_commit[0], 'date':init_commit[1]}

    #If not the initial commit, traverse the ancestry path
    next_commits = git.Git( git_dir ).log('--reverse', '--ancestry-path', commit_hexsha + '^..master', '--format="%an;%at;%P"').split('\n')

    #Remove quotes
    for l in range(0,len(next_commits)):
        next_commits[l] = next_commits[l][1:-1]

    if len(next_commits) > 0:
        if len(next_commits) > 1:
            next_commit = next_commits[1].rsplit(';',2)

            #Check if branch is merged
            if len(next_commit) == 3:
                auth = next_commit[0]
                date = next_commit[1]
                hexsha = next_commit[2]

                if len(hexsha.split(' ')) == 2:
                    if commit_hexsha == hexsha.split(' ')[0] or commit_hexsha == hexsha.split(' ')[1]:
                        #Merged branch commit: return merge author, e.g. author of the child commit
                        return {'author':auth, 'date':date}

            #Check if commit is a direct change to Git
            else:
                commit = next_commits[0].rsplit(';',2)

                if len(commit) == 3:
                    auth = commit[0]
                    date = commit[1]

                    #Commit is the most recent one in the master branch, which occurs during a direct change to the repo without a merge: approver is commit author
                    return {'author':auth, 'date':date}

        #Check if the branch is not a direct commit, but also not a merge
        curr_ad = git.Git( git_dir ).log('--reverse', '--ancestry-path', commit_hexsha + '^..' + commit_hexsha, '--format="%an;%at"').rsplit(';',1)
        if len(curr_ad) == 2:
            #Strip quotes
            auth = curr_ad[0][1:]
            date = curr_ad[1][:-1]

            #Commit is not a direct commit, nor a merge
            return {'author':auth, 'date':date}

    #No auth/date found, return n/a
    return {'author':'n/a', 'date':'n/a'}

def get_added_deleted_rules( git_dir, yamlfile ):
    added_deleted_rules = {'added':[], 'deleted':[], 'added_previously':[]}
    commits_rules_list = []

    #Get commit history for file
    adh_list = git.Git( git_dir ).log('--format="%an;%at;%H"', '--follow', yamlfile).split('\n')

    #Remove quotes
    for l in range(0,len(adh_list)):
        adh_list[l] = adh_list[l][1:-1]

    for adh in adh_list:
        if len(adh):
            author = adh.split(';',2)[0]
            date = adh.split(';',2)[1]
            commit_hexsha = adh.split(';',2)[2]

            #Get yaml file and load its contents, unless the group doesn't exist in the current commit yet
            try:
                yamlfile_data = git.Git( git_dir ).show(commit_hexsha + ':' + yamlfile)
            except git.exc.GitCommandError:
                continue

            if len(yamlfile_data) == 0:
                continue

            try:
                rules = state.load(yamlfile_data)

            #Past version of the yaml file had a formatting error
            except yaml.scanner.ScannerError:
                continue
            except TypeError:
                continue

            if 'rules' in rules:
                rules = rules['rules']

            rules_dict = {}
            if len(rules) == 0:
                rules = [{}]

            if type(rules) is dict:
                rules = [rules]

            for rule in rules:
                rule['hexsha'] = commit_hexsha
                rule['author'] = author
                rule['date'] = date
                rules_dict[get_hash_from_rule(rule)] = rule

            commits_rules_list.append(rules_dict)

    #Reverse so that commits are in chronological order - this way, we implicitly know which commits are earliest
    commits_rules_list.reverse()

    #Add all rules from initial commit into 'added'
    if len(commits_rules_list) > 0:
        for rule_hash in commits_rules_list[0]:
            init_added_rule = commits_rules_list[0][rule_hash].copy()
            added_deleted_rules['added'].append(init_added_rule)

    #Get added and deleted by comparing each pair of sequential commits
    if len(commits_rules_list) > 1 and len(commits_rules_list[0].values()) > 0:
        for i in range(0,len(commits_rules_list)-1):
            commit = commits_rules_list[i]
            commit_next = commits_rules_list[i+1]

            for rule_hash in commit_next:
                if not rule_hash in commit:
                    added_rule = commit_next[rule_hash].copy()
                    added_deleted_rules['added'].append(added_rule)

            for rule_hash in commit:
                if not rule_hash in commit_next:
                    deleted_rule = commit[rule_hash].copy()

                    #Set author, date, and hexsha to those of commit_next
                    deleted_rule['author'] = commit_next.values()[0]['author']
                    deleted_rule['date'] = commit_next.values()[0]['date']
                    deleted_rule['hexsha'] = commit_next.values()[0]['hexsha']

                    added_deleted_rules['deleted'].append(deleted_rule)

                    #Move this rule from 'added' to 'added_previously'
                    for ar in added_deleted_rules['added']: 
                        if get_hash_from_rule(deleted_rule) == get_hash_from_rule(ar):
                            added_deleted_rules['added_previously'].append(
                                added_deleted_rules['added'].pop( added_deleted_rules['added'].index(ar)) )

    #Reverse added_deleted_rules so that they are in reverse chronological order - the most recent rule changes should show first
    added_deleted_rules['added'].reverse()
    added_deleted_rules['deleted'].reverse()
    added_deleted_rules['added_previously'].reverse()

    return added_deleted_rules

@contextlib.contextmanager
def repo(repo, sha1=None):
    git_dir, is_clone_url = get_valid_repo(repo)
    if sha1:
        git.Git(git_dir).checkout(sha1)
    yield git_dir
    if is_clone_url:
        shutil.rmtree(git_dir)

def get_connection(vpc_id, region, **k):
    c = boto.vpc.connect_to_region(region, **k)
    if c:
        vpcs = dict((x.id, x) for x in c.get_all_vpcs())

        if vpc_id in vpcs:
            conn = vpcs[vpc_id].connection

            # Monkey patch get_only_instances/get_all_security_groups
            orig_get_only_instances = conn.get_only_instances
            orig_get_all_security_groups = conn.get_all_security_groups
            def get_only_instances(**k):
                k.setdefault('filters', {})
                k['filters'].setdefault('vpc-id', vpc_id)
                return orig_get_only_instances(**k)
            def get_all_security_groups(**k):
                k.setdefault('filters', {})
                k['filters'].setdefault('vpc-id', vpc_id)
                return orig_get_all_security_groups(**k)
            conn.get_only_instances = get_only_instances
            conn.get_all_security_groups = get_all_security_groups

            return conn

def get_id_for_group(conn, sgname):
    for sg in conn.get_all_security_groups(filters={'group-name': sgname}):
        return sg.id

def get_hexsha(repo):
    return git.Repo(repo).heads.master.commit.hexsha
