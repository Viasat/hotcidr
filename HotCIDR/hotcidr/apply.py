#!/usr/bin/python
#server
import time
import sys
import datetime
from subprocess import Popen, PIPE
import yaml
import hashlib
import boto.ec2
import os
import os.path
import argparse

import hotcidr
from hotcidr import fetchvpc
from hotcidr import notifyemail
from hotcidr import modifydatabase
from hotcidr import gitlib

sum_rulesAuth = 0
sum_rulesRev = 0
sum_secGroupAuth = 0
sum_secGroupRev = 0

def cleanGroupAndDelete(secGroup):
    #delete all security rules to be allow deleting group without dependent object error
    print 'Cleaning group to be deleted  %s' % secGroup.name
    for group in securityGroups:
        if group.name == secGroup.name:
            for rule in group.rules_egress:
                if 'sg' in str(rule.grants):
                    connection.revoke_security_group_egress(ip_protocol = rule.ip_protocol,
                                                            to_port = rule.to_port,
                                                            from_port = rule.from_port,
                                                            group_id = group.id,
                                                            src_group_id = str(rule.grants[0])[:11]
                                                           )
                else:
                    connection.revoke_security_group_egress(ip_protocol = rule.ip_protocol,
                                                            to_port = rule.to_port,
                                                            from_port = rule.from_port,
                                                            group_id = group.id,
                                                            cidr_ip = rule.grants[0]
                                                           )
    for group in securityGroups:
        if group.name == secGroup.name:
            for rule in group.rules:
                if 'sg' in str(rule.grants):
                    connection.revoke_security_group(ip_protocol = rule.ip_protocol,
                                                     to_port = rule.to_port,
                                                     from_port = rule.from_port,
                                                     group_name = group.name,
                                                     group_id = group.id,
                                                     src_security_group_group_id = str(rule.grants[0])[:11]
                                                    )
                else:
                    connection.revoke_security_group(ip_protocol = rule.ip_protocol,
                                                     to_port = rule.to_port,
                                                     from_port = rule.from_port,
                                                     group_name = group.name,
                                                     group_id = group.id,
                                                     cidr_ip = rule.grants[0]
                                                    )

# function revokes any security rule that was improperly entered directly into AWS
def revokeFromAWSBasedOnGit(connection, ec2Instances, masterRepo, securityGroups):
    print '\n\n\nRevoking rules from AWS that are not consistent with the Git: '

    global sum_rulesRev

    #load yaml into python dictionaryies
    awsYaml = gitlib.get_groups_dict('AWS_out')

    checkSecGroups = []

    #iterates through ec2 instances creating identifier dictionaries for each associated security group
    for key,val in ec2Instances.iteritems():
        for eachSecGroup in val['groups']:
            if eachSecGroup in checkSecGroups:
                continue
            else:
                checkSecGroups.append(eachSecGroup)
            #print 'eachSecGroup: %s' % eachSecGroup
            awsCopy = open( os.path.join('AWS_out', awsYaml[str(eachSecGroup)]), 'rU')
            gitCopy = open( os.path.join(masterRepo, awsYaml[str(eachSecGroup)]), 'rU' )
            #print 'gitCopy %s' % gitCopy
            groupBeingExamined = awsYaml[(eachSecGroup)].rstrip('.yaml')[7:]

            awsRulesIter =  hotcidr.state.load(awsCopy)
            gitRulesIter = hotcidr.state.load(gitCopy)
            #print 'gitRulesIter %s' % gitRulesIter

            awsRulesComp = {}
            gitRulesComp = {}

            #make dict of unique identifiers for each rule in AWS
            for aK, aV in awsRulesIter.iteritems():
                if aK == 'rules':
                    for eachElem in aV:
                        mustHaveFollowingKeys = { 'direction', 'protocol', 'description', 'ports','location'}
                        if not all(key in eachElem for key in mustHaveFollowingKeys):
                            continue

                        if not hasattr(eachElem['ports'], 'toport') or not hasattr(eachElem['ports'], 'fromport'):
                            continue

                        identifier = (str(eachElem['direction'])
                                      + str(eachElem['protocol'])
                                      + str(eachElem['description'])
                                      + str(eachElem['ports'].toport)
                                      + str(eachElem['ports'].fromport)
                                      + str(eachElem['location'])
                                     )

                        hash = hashlib.md5()
                        hash.update(identifier)
                        awsRulesComp[str(hash.digest())] = eachElem

            #make dict of unique identifiers for each rule in Git
            for gK, gV in gitRulesIter.iteritems():
                if gK == 'rules':
                    for eachElem in gV:
                        mustHaveFollowingKeys = { 'direction', 'protocol', 'description', 'ports','location'}
                        if not all(key in eachElem for key in mustHaveFollowingKeys):
                            continue

                        if not hasattr(eachElem['ports'], 'toport') or not hasattr(eachElem['ports'], 'fromport'):
                            continue

                        identifier = (str(eachElem['direction'])
                                      + str(eachElem['protocol'])
                                      + str(eachElem['description'])
                                      + str(eachElem['ports'].toport)
                                      + str(eachElem['ports'].fromport)
                                      + str(eachElem['location'])
                                     )

                        hash = hashlib.md5()
                        hash.update(identifier)
                        gitRulesComp[str(hash.digest())] = eachElem


            #iterates through each associated security group checking if both dicts have each rules' unique identifier
            #perform actual check of AWS against the Git to see any inconsistencies
            for awsKey, awsVal in awsRulesComp.iteritems():
                if awsKey not in gitRulesComp.keys():
                    #print 'awsKey %s, awsVal %s' % (awsKey, awsVal)
                    #if not, find group being examined and revoke the rule
                    for eachGroup in securityGroups:
                        if eachGroup.name == groupBeingExamined.rstrip('.yaml') :
                            if isinstance(awsVal['protocol'], int):
                                awsVal['ports'].fromport = None
                                awsVal['ports'].toport = None
                            if awsVal['protocol'] == 'all':
                                awsVal['protocol'] = '-1'
                            if awsVal['direction'] == 'inbound':
                                #remove inbound with security group source
                                if 'sg' in awsVal['location']:
                                    connection.revoke_security_group(eachGroup.name,
                                                                     ip_protocol = awsVal['protocol'],
                                                                     from_port = awsVal['ports'].fromport,
                                                                     to_port = awsVal['ports'].toport,
                                                                     group_id = eachGroup.id,
                                                                     src_security_group_group_id = awsVal['location'],
                                                                    )
                                #remove inbound with CIDR IP source
                                else:
                                    connection.revoke_security_group(eachGroup.name,
                                                                     ip_protocol = awsVal['protocol'],
                                                                     from_port = awsVal['ports'].fromport,
                                                                     to_port = awsVal['ports'].toport,
                                                                     cidr_ip = awsVal['location'],
                                                                     group_id = eachGroup.id,
                                                                    )

                            else:
                                #remove outbound with security group source
                                if 'sg' in awsVal['location']:
                                    connection.revoke_security_group_egress(eachGroup.id,
                                                                            ip_protocol = awsVal['protocol'],
                                                                            from_port = awsVal['ports'].fromport,
                                                                            to_port = awsVal['ports'].toport,
                                                                            src_group_id = awsVal['location'],
                                                                            cidr_ip = None,
                                                                           )
                                #remove outbound with CIDR IP source
                                else:
                                    connection.revoke_security_group_egress(eachGroup.id,
                                                                            ip_protocol = awsVal['protocol'],
                                                                            from_port = awsVal['ports'].fromport,
                                                                            to_port = awsVal['ports'].toport,
                                                                            src_group_id = None,
                                                                            cidr_ip = awsVal['location'],
                                                                           )

                            print ('\n\nrevoking rule from group : ' + str(groupBeingExamined)
                                    + '\n\ndirection: ' + str(awsVal['direction'])
                                    + '\nip_protocol: ' + str(awsVal['protocol'])
                                    + '\nfrom_port: ' + str(awsVal['ports'].fromport)
                                    + '\nto_port: ' + str(awsVal['ports'].toport)
                                    + '\nlocation: ' + str(awsVal['location'])
                                    + '\ndescription: ' + str(awsVal['description']) + '\n'
                            )

                            sum_rulesRev = sum_rulesRev + 1
                            mySQLdict = { 'groupID' : eachGroup.id,
                                          'modifiedGroup': groupBeingExamined,
                                          'direction': awsVal['direction'],
                                          'added_or_revoked' : 0,
                                          'protocol' : awsVal['protocol'],
                                          'fromport' : awsVal['ports'].fromport,
                                          'toport':awsVal['ports'].toport,
                                          'location':awsVal['location'],
                                          'description': awsVal['description'],
                                          'justification' : 'none'
                                        }

                            #add to mySQL Database
                            modifydatabase.modifyTable(mySQLdict)
                            try:
                                #generate notification for improperly added rule (bypassing Git)
                                notifyemail.notifyGitBypass(mySQLdict)
                            except:
                                print 'No server entered for SMTP'
                                continue

def addToAWSBasedOnGit(connection, ec2Instances, masterRepo, securityGroups, is_clone_url):
    print '\n\n\nNow populating AWS with any missing rules from the Git: '

    global sum_rulesAuth

    awsYaml = gitlib.get_groups_dict('AWS_out')

    checkSecGroups = []

    for key,val in ec2Instances.iteritems():
        #print 'key %s, val %s' % (key, val)
        for eachSecGroup in val['groups']:
            if eachSecGroup in checkSecGroups:
                #print 'continunig %s' % eachSecGroup
                #print 'checkSecGroups %s' % checkSecGroups
                continue
            else:
                checkSecGroups.append(eachSecGroup)
            #print 'AeachSecGroup: %s' % eachSecGroup
            awsCopy = open(os.path.join( 'AWS_out', awsYaml[str(eachSecGroup)]), 'rU')
            gitCopy = open(os.path.join( masterRepo, awsYaml[str(eachSecGroup)]), 'rU')

            groupBeingExamined = awsYaml[(eachSecGroup)].rstrip('.yaml')[7:]

            awsRulesIter =  hotcidr.state.load(awsCopy)
            gitRulesIter = hotcidr.state.load(gitCopy)

            awsRulesComp = {}
            gitRulesComp = {}

            #make dict of unique identifiers for each rule in AWS
            for aK, aV in awsRulesIter.iteritems():
                if aK == 'rules':
                    for eachElem in aV:
                        mustHaveFollowingKeys = { 'direction', 'protocol', 'description', 'ports','location'}
                        if not all(key in eachElem for key in mustHaveFollowingKeys):
                            #print 'CONT1'
                            continue
                        if not hasattr(eachElem['ports'], 'toport') or not hasattr(eachElem['ports'], 'fromport'):
                            #print 'CONT2'
                            continue

                        identifier = (str(eachElem['direction'])
                                      + str(eachElem['protocol'])
                                      + str(eachElem['description'])
                                      + str(eachElem['ports'].toport)
                                      + str(eachElem['ports'].fromport)
                                      + str(eachElem['location'])
                                     )
                        hash = hashlib.md5()
                        hash.update(identifier)
                        awsRulesComp[str(hash.digest())] = eachElem

            #make dict of unique identifiers for each rule in Git
            for gK, gV in gitRulesIter.iteritems():
                if gK == 'rules':
                    for eachElem in gV:
                        mustHaveFollowingKeys = { 'direction', 'protocol', 'description', 'ports','location'}
                        if not all(key in eachElem for key in mustHaveFollowingKeys):
                            #print 'CONT3'
                            continue
                        if not hasattr(eachElem['ports'], 'toport') or not hasattr(eachElem['ports'], 'fromport'):
                            #print 'CONT4'
                            continue

                        identifier = (str(eachElem['direction'])
                                      + str(eachElem['protocol'])
                                      + str(eachElem['description'])
                                      + str(eachElem['ports'].toport)
                                      + str(eachElem['ports'].fromport)
                                      + str(eachElem['location'])
                                     )
                        hash = hashlib.md5()
                        hash.update(identifier)
                        gitRulesComp[str(hash.digest())] = eachElem

            for gitKey, gitVal in gitRulesComp.iteritems():
                #print 'gitkey %s gitVal %s' % (gitKey, gitVal)
                if gitKey not in awsRulesComp.keys():
                    #print 'gitkey %s gitVal %s' % (gitKey, gitVal)
                    for eachGroup in securityGroups:
                        if eachGroup.name == groupBeingExamined.rstrip('.yaml'):
                            if isinstance(gitVal['protocol'], int):
                                gitVal['ports'].fromport = None
                                gitVal['ports'].toport = None
                            if gitVal['protocol'] == 'all':
                                gitVal['protocol'] == '-1'
                            if gitVal['direction'] == 'inbound':
                                if 'sg' in gitVal['location']:
                                    #authorize inbound with source security group
                                    connection.authorize_security_group(eachGroup.name,
                                                                       ip_protocol = gitVal['protocol'],
                                                                       from_port = gitVal['ports'].fromport,
                                                                       to_port = gitVal['ports'].toport,
                                                                       src_security_group_group_id = gitVal['location'],
                                                                       #group_id = eachGroup.id
                                                                      )
                                else:
                                    #authorize inbound with source CIDR IP
                                    connection.authorize_security_group(eachGroup.name,
                                                                       ip_protocol = gitVal['protocol'],
                                                                       from_port = gitVal['ports'].fromport,
                                                                       to_port = gitVal['ports'].toport,
                                                                       cidr_ip = gitVal['location'],
                                                                       #group_id = eachGroup.id
                                                                      )

                            else:
                                if 'sg' in gitVal['location']:
                                    #authorize outbound with source security group
                                    connection.authorize_security_group_egress(eachGroup.id,
                                                                               ip_protocol = gitVal['protocol'],
                                                                               from_port = gitVal['ports'].fromport,
                                                                               to_port = gitVal['ports'].toport,
                                                                               src_group_id = gitVal['location'],
                                                                               cidr_ip = None,
                                                                              )
                                else:
                                    #authorize outbound with CIDR IP
                                    connection.authorize_security_group_egress(eachGroup.id,
                                                                               ip_protocol = gitVal['protocol'],
                                                                               from_port = gitVal['ports'].fromport,
                                                                               to_port = gitVal['ports'].toport,
                                                                               src_group_id = None,
                                                                               cidr_ip = gitVal['location'],
                                                                              )
                            print ('\n\nauthorizing rule into group : ' + str(groupBeingExamined)
                                       + '\n\ndirection: ' + str(gitVal['direction'])
                                       + '\nip_protocol: ' + str(gitVal['protocol'])
                                       + '\nfrom_port: ' + str(gitVal['ports'].fromport)
                                       + '\nto_port: ' + str(gitVal['ports'].toport)
                                       + '\nlocation: ' + str(gitVal['location'])
                                       + '\ndescription: ' + str(gitVal['description']) + '\n'
                                     )

                            sum_rulesAuth = sum_rulesAuth + 1
                            #add new or restored rule to mySQL database
                            mySQLdict = { 'groupID':eachGroup.id,
                                          'modifiedGroup':groupBeingExamined,
                                          'direction': gitVal['direction'],
                                          'added_or_revoked' : 1,
                                          'protocol' : gitVal['protocol'],
                                          'fromport' : gitVal['ports'].fromport,
                                          'toport':gitVal['ports'].toport,
                                          'location':gitVal['location'],
                                          'description': gitVal['description'],
                                          'justification' : 'none'
                                        }
                            modifydatabase.modifyTable(mySQLdict)

#delete local copies of AWS and Git repositories
def deleteLocalRepos():
    print '\n'
    p = Popen(['rm', '-R', 'AWS_out'], stdin=PIPE, stdout=PIPE, universal_newlines=True)
    #answer all override prompts with'y'
    for line in p.stdout:
        if line.startswith('override'):
            answer = 'y'
        else:
            continue
        file = p.stdin
        print answer
        p.stdin.flush()

def main(masterRepo, is_clone_url, awsRegion,  awsId, awsPword):

    connection = boto.ec2.connect_to_region(awsRegion, aws_access_key_id= awsId, aws_secret_access_key = awsPword)
    securityGroups = connection.get_all_security_groups()

    global sum_secGroupAuth
    global sum_secGroupRev
    global sum_rulesAuth
    global sum_rulesRev

    print 'Updating AWS environment to reflect current security groups\n'

    #fetches all of the AWS security groups and outputs .yaml files for each in AWS_out dir
    fetchvpc.main(awsRegion, 'AWS_out', access_id = awsId, access_key = awsPword)

    #fetches all of the ec2 instances and outputs .yaml files to access their security groups
    openBoxesAWS = open(os.path.join('AWS_out','boxes.yaml'), 'rU')
    ec2Original = yaml.load(openBoxesAWS)

    openBoxesGit = open(os.path.join(masterRepo, 'boxes.yaml'), 'rU')
    gitInstances = yaml.load(openBoxesGit)

    secGroupsAWS = []

    #get the git repository
    AWSFiles = os.listdir('AWS_out/')
    for eachFile in AWSFiles:
        possibleDir = os.path.join('AWS_out', str(eachFile))
        if os.path.isdir(possibleDir):
            for eachElem in os.listdir(possibleDir):
                AWSFiles.append(eachElem)
                if 'groups' in possibleDir:
                    secGroupsAWS.append(eachElem)

    secGroupsMaster = []

    masterFiles = os.listdir(masterRepo)
    for eachFile in masterFiles:
        possibleDir = os.path.join(str(masterRepo),  str(eachFile))
        if os.path.isdir(possibleDir):
            for eachElem in os.listdir(possibleDir):
                masterFiles.append(eachElem)
                if 'groups' in possibleDir:
                    secGroupsMaster.append(eachElem)

    groupsYaml = gitlib.get_groups_dict(masterRepo)


    for eachGroup in secGroupsMaster:
        if eachGroup not in secGroupsAWS:
            #group in master thats not in aws --> should be added
            #try:
            print '\nAuthorizing following security group from master repository: %s' % eachGroup
            connection.create_security_group(str(eachGroup).rstrip('.yaml'), 'no description')
            openAdd = open(os.path.join(masterRepo, groupsYaml[str(eachGroup).rstrip('.yaml')]), 'rU')
            addYaml = yaml.load(openAdd)
            for each in connection.get_all_security_groups():
                if each.name == str(eachGroup).rstrip('.yaml'):
                    addYaml['id'] = each.id
                    with open(os.path.join(masterRepo, groupsYaml[str(eachGroup).rstrip('.yaml')]), 'w') as outfile:
                        outfile.write(yaml.dump(addYaml, default_flow_style=False))
            #to add security group -> must add associations to boxes.yaml 1) adds groups 2) does association 3) should populate
            sum_secGroupAuth = sum_secGroupAuth + 1
            #except:
            #  print '\nError authorizing security group %s into AWS Network, continuing script...' % eachGroup
            #  continue

    securityGroups = connection.get_all_security_groups()
    secGroupIDs = {}
    for eachSG in securityGroups:
        #print 'eachSG %s' % eachSG
        secGroupIDs[str(eachSG.name.replace('-', ''))] = eachSG.id

    #print 'secGroupsIDs %s' % secGroupIDs

    for eachInstance in connection.get_only_instances():
        newAssoc = []
        if str(eachInstance.id) not in gitInstances:
            sys.exit(1)
        for eachG in gitInstances[str(eachInstance.id)]['groups']:
            newAssoc.append(secGroupIDs[str(eachG).replace('-', '')])
        connection.modify_instance_attribute(eachInstance.id, 'groupSet', newAssoc, dry_run=False)

    for eachGroup in secGroupsAWS:
        if eachGroup not in secGroupsMaster:
            for eachG in connection.get_all_security_groups():
                if eachG.name == eachGroup.rstrip('.yaml'):
                    print '\nDeleting following security group from AWS that was not found in master repository: %s' % eachGroup
                    try:
                        eachG.delete()
                    except:
                        cleanGroupAndDelete(eachG)
                    sum_secGroupRev = sum_secGroupRev + 1

    securityGroups = connection.get_all_security_groups()

    deleteLocalRepos()

    print 'Updating AWS security groups to reflect current rules in Git repository\n'

    #fetches all of the AWS security groups and outputs .yaml files for each in AWS_out dir
    fetchvpc.main(awsRegion,'AWS_out', access_id = awsId, access_key = awsPword)

    #fetches all of the ec2 instances and outputs .yaml files to access their security groups
    openBoxesAWS = open(os.path.join('AWS_out', 'boxes.yaml'), 'rU')
    ec2Instances = yaml.load(openBoxesAWS)

    revokeFromAWSBasedOnGit(connection, ec2Instances, masterRepo, securityGroups)
    addToAWSBasedOnGit(connection, ec2Instances, masterRepo, securityGroups, is_clone_url)
    #random security groups

    deleteLocalRepos()
    if is_clone_url:
        gitlib.remove_git_repo()

    current = datetime.datetime.now()
    currStr = str(current).rstrip('datetime.datetime')
    finalStr = str(currStr[:19])

    print '\n\n*********************** Ending hc-apply run at %s**********************\n' % finalStr



    print '%s Groups Added, %s Groups Revoked, %s Rules Added, %s Rules Revoked' % (sum_secGroupAuth, sum_secGroupRev, sum_rulesAuth, sum_rulesRev)
