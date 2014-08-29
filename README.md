Hot CIDR
========

Hot CIDR provides tools for firewall rule management and automation. The
toolchain currently supports AWS. Expansion to other popular infrastructures
is in the works.

Table of Contents
-----------------

 - [Workflows](#workflow)
 - [Setup](#setup)
 - [Documentation](#documentation)
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
% hc-fetch-amazon fw_rules
```

Setup as git repository

```
% cd fw_rules
fw_rules% git init
fw_rules% git add .
fw_rules% git commit -m "Initial commit"
fw_rules% git remote add origin YOUR_REPO_URL
fw_rules% git push -u origin master
```


### Automatic rule application (TODO)
Setup cronjob for hc-apply to run in background (script runs on interval in background) 
1. Run `crontab -e` in unix shell to open up cronjob config file
   
2. Add following line to end of cronjob config file (15 signifies script will run every 15 minutes)
   
    SHELL=/bin/bash
    */15 * * * * cd ~/hotcidr/HotCIDR/bin/; hc-apply GITURL >> ~/hotcidr/HotCIDR/applyLog/log\_apply

3. Script will maintain consistency between GitRepository and AWS while logging output in "applyLog"


Documentation
-------------
TBD :/


Authors
-------
This code was initially written by Justin Bass, James Kwan, and Austin Solomon.


Copyright and License
---------------------
Code and documentation copyright 2014 ViaSat, Inc. Code is released under [the
Apache 2.0 license](LICENSE).
