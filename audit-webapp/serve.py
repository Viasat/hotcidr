#!/usr/bin/env python2
import flask
import os
import subprocess
import tempfile
import time
app = flask.Flask('audit-app')
outdir='out/'
assert(outdir[-1] == '/')

@app.route('/create', methods=['POST'])
def job_create():
    try:
        start = ['--from-time', '%d' % time.mktime(time.strptime(flask.request.form['startdate'], '%Y-%m-%d'))]
    except Exception:
        start = []
    try:
        end = ['--to-time', '%d' % time.mktime(time.strptime(flask.request.form['enddate'], '%Y-%m-%d'))]
    except Exception:
        end = []
    ruleset = flask.request.form['ruleset']
    out = tempfile.mkdtemp(prefix='job_', dir=outdir)
    subprocess.Popen(['./audit.py', out, ruleset] + start + end, cwd=os.getcwd())
    return "%s" % out[len(outdir):]

if __name__ == "__main__":
    app.run()
