from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.Utils import formatdate

import smtplib

date_fmt = '%m/%d/%y %H:%M'

def notifyGitBypass(ruleDict):

    me = '__FILL_IN_HERE__'
    to = ['__FILL_IN_HERE__']

    # Create the container (outer) email message.
    msg = MIMEMultipart()
    msg['Subject'] = 'Firewall rule bypassed Git Repository'
    msg['From'] = me
    msg['Reply-To'] = '__FILL_IN_HERE__'
    msg['To'] = '__FILL_IN_HERE__'
    msg['Date'] = formatdate(usegmt=True)

    #format message with rule
    message = MIMEText("""From: HotCIDR
    To: Network Administrator
    Subject:

    The following rule was entered directly into AWS without first being entered into the Git Repository. (May be malicious)

    Removed from AWS Security Group: %s
    With GroupID: %s

    Direction: %s
    IP Protocol: %s
    Port Range: from port %s to port %s
    Source: %s
    Description: %s

    It was subsequenty removed and added to the DELETED_RULES database for use in the Firewall Audit.
    """ % (ruleDict['modifiedGroup'], ruleDict['groupID'], ruleDict['direction'], ruleDict['protocol'], ruleDict['fromport'], ruleDict['toport'], ruleDict['location'], ruleDict['description']))


    msg.attach(message)

    # Send the email via our own SMTP server.
    s = smtplib.SMTP('__SMTP_SERVER_HERE__')
    s.sendmail(me, to, msg.as_string())
    s.quit()
