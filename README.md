Hot CIDR
========

Hot CIDR provides tools for firewall rule management and automation. The
toolchain currently supports AWS. Expansion to other popular infrastructures
is in the works.

Table of Contents
-----------------

 - [Workflows](#workflow)
 - [Setup](#setup)
 - [Documentation Notes](#documentation-notes)
 - [Authors](#authors)
 - [Copyright and license](#copyright-and-license)

Workflow
--------
### User wishes to update firewall rules
 - User clones firewall rules repository
 - User commits changes to local version
 - User submits commit as a pull request
 - Network administrator approves/merges

Setup
-----
### Toolchain installation
Optional: setup and activate python virtual environment

```
% virtualenv venv
% source venv/bin/activate
```

Clone repository and install

```
% git clone 'https://github.com/viasat/hotcidr'
% cd hotcidr/HotCIDR
HotCIDR% python setup.py install
```


### Jenkins CI Setup
- Install jenkins and configure
- Install and configure [ghprb plugin](https://git.viasat.com/jkwan/ghprb-fork#installation)
- Customize provided validate script for running the job


### Audit Webapp
See [README](audit-webapp/README.md)


### Repository setup
Fetch the VPC

```
% hc-fetch <vpc-region-code> <output-directory> AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

e.g.
% hc-fetch us-west-2 ./us-west-2-core AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

```

Setup as git repository

```
% cd fw_rules
fw_rules% git init
fw_rules% git add .
fw_rules% git commit -m "Initial commit"
fw_rules% git remote add origin <YOUR_REPO_URL>
fw_rules% git push -u origin master
```

Documentation Notes
-------
### Apply
Apply takes a valid ruleset repository and applies the rules to the EC2 VPC.

Apply will not work for rules that are incorrectly formatted.

### Audit
Auditing can be done from the [dashboard](dashboard/README.md), or from the command line where HotCIDR is installed:

    hc-audit <repo>

The <repo> can be either a local git repository (a local directory) or a remote git repository (a git url, either https or ssh).

The security group ids for each group will be added in if four arguments are present or can be obtained automatically: aws-access-key-id & aws-secret-access-key (if not present, will be obtained from boto configuration, e.g. ~/.boto), the vpc-id (which is not necessary if no conflicting security group names exist, e.g. there is only one vpc), and the region-code (always necessary, although in future versions, it can be obtained from the vpc-id if present).

Note that in the dashboard, unauthorized rules will be printed, which is not true for the command line. This is because the dashboard automatically configures the MySQL database necessary for unauthorized rules. The code is commented out in the apply script, if this functionality is added in the future.

### Expirations

For testing or safety purposes, certain rules can be set to expire. For example, a rule allowing all inbound traffic with any port and protocol is probably meant for temporary testing, and can be tagged to expire after a reasonable time period.

The script hc-deleteexpired must be run periodically on the desired repo. It will look for rule expirations, and then commit and push changes to the repo automatically. Because rule expiration is automatic and can delete things from the repo, **exercise caution**.

There are two ways to cause a rule to expire:

1. Add an 'expiration' field to any rule in a group's yaml file.
2. Add matching rule fields into expirations.yaml as criteria for expirations

Here is an example of the first kind of expiration:

```
security_group_1.yaml
---
rules:
- direction: inbound
  protocol: all
  location: 0.0.0.0/0
  expiration: 86400
```

This will cause this single, specific rule to be removed 1 day after it was committed.

Here is an example of the second kind of expiration:

```
expirations.yaml
---
rules:
- direction: inbound
  protocol: all
  location: 0.0.0.0/0
  expiration: 86400 
```

This example will cause any rule in the entire repository matching the direction, protocol and location fields to be removed 1 day after it was committed.

**Be careful with this**, as writing something such as

```
expirations.yaml
---
rules:
- ports: 443
  expiration: 1
```

Will cause every rule in the entire repo with 'ports: 443' to be deleted instantly. 


Authors
-------
This code was initially written by [Justin Bass](http://www.justinalanbass.com), James Kwan, and Austin Solomon.


Copyright and License
---------------------
Code and documentation copyright 2014 ViaSat, Inc. Code is released under [the Apache 2.0 license](LICENSE).
