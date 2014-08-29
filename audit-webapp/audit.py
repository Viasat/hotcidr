#!/usr/bin/env python2
import csv
import datetime
import fcntl
import jinja2
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile

auditor = 'hc-audit'

out = sys.argv[1]
ruleset = sys.argv[2]
jid = os.path.basename(out.rstrip('/'))
dl = '%s.csv' % jid

raw_out = os.path.join(out, dl)
html_out = os.path.join(out, 'index.html')
stat_out = os.path.join(out, 'status')

blog = ''
prog = '0'
stat = ''
done = False
def log(s):
    global stat, blog
    stat = s
    blog += '%s\n' % s
    update_status()

def timestamp():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def nonblocking(f):
    flags = fcntl.fcntl(f, fcntl.F_GETFL)
    fcntl.fcntl(f, fcntl.F_SETFL, flags | os.O_NONBLOCK)

def handle_err(s):
    global prog
    if s.startswith('Progress: '):
        prog = s[10:]
        update_status()
    else:
        log(s)

def update_status():
    with open(stat_out, 'w+') as f:
        f.write(json.dumps({
            'done': done,
            'status': stat,
            'progress': prog
        }))

def unsegment(s):
    r = []
    for i in s:
        if i == ['---']:
            yield r
            r = []
        else:
            r.append(i)
    yield r

log("# Job started %s" % timestamp())

# Clone ruleset
gitdir = tempfile.mkdtemp()
log("$ git clone %s %s" % (ruleset, gitdir))
try:
    devnull = open(os.devnull, 'w')
    subprocess.check_call(['git', 'clone', ruleset, gitdir],
                          stdout=devnull,
                          stderr=devnull)
except subprocess.CalledProcessError as e:
    log("Could not clone ruleset %s, git returned %d" % (ruleset, e.returncode))
    sys.exit(1)

# Begin audit script
args = sys.argv[3:] + ['--output-webserver']
log("$ python2 %s %s %s" % (os.path.basename(auditor),
                          gitdir,
                          ' '.join(args)))
p = subprocess.Popen(['python2', auditor, gitdir] + args,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     cwd=os.getcwd())
nonblocking(p.stdout)
nonblocking(p.stderr)

# Buffer audit script output
raw = ''
buf = ''
while True:
    rs, _, _ = select.select([p.stdout, p.stderr], [], [], 0.5)

    for r in rs:
        if r is p.stdout:
          raw += p.stdout.read()
        if r is p.stderr:
          buf += p.stderr.read()
          while '\n' in buf:
              l, _, buf = buf.partition('\n')
              handle_err(l)

    if p.poll() != None:
        break
if buf != '':
    handle_err(buf)
shutil.rmtree(gitdir)

# Save raw output
with open(raw_out, 'w') as o:
    o.write(raw)

log("# Job completed %s" % timestamp())

# Pretty print
env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
template = env.get_template('job_out.html')
with open(html_out, 'w') as o:
    data = csv.reader(raw.splitlines())
    e = [{
        'id': x[0][0] if len(x[0]) > 0 else None,
        'name': x[0][1] if len(x[0]) > 1 else None,
        'machines': x[2],
        'rules': [{
            'action': y[0],
            'protocol': y[1],
            'ports': y[2],
            'direction': y[3],
            'type': y[4],
            'location': y[5],
            'proposed': "%s by %s" % (y[7], y[6]),
            'approved': "%s by %s" % (y[9], y[8]),
            'justification': y[10],
            'description': y[11]
        } for y in x[4:] if len(y) > 11]
    } for x in unsegment(data) if len(x) > 4]

    o.write(template.render(entries=e, download=dl, build_log=blog).encode('utf-8'))

done = True
update_status()
