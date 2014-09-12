from hotcidrdash import app
from hotcidrdash import db
from hotcidrdash import util
from celery import Celery
from crontab import CronTab
import csv
import datetime
import flask
import json
import subprocess
import threading
import time
try:
    import queue
except ImportError:
    import Queue as queue

def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery

app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379',
    CELERY_RESULT_BACKEND='redis://localhost:6379'
)
app.user_options = {'preload': False}
celery = make_celery(app)

def schedule_apply(config):
    cmd = 'curl %s' % flask.url_for('apply', slug=config.slug, _external='127.0.0.1:5000')
    cron = CronTab()

    existing = cron.find_command(cmd)
    try:
        job = next(existing)
        for j in existing:
            cron.remove(j)
    except StopIteration:
        job = cron.new(command=cmd)

    try:
        job.every(int(str(config.cron))).minutes()
    except ValueError:
        assert(job.setall(config.cron))

    cron.write()

def run_apply(config, title="hc-apply"):
    entry = db.ApplyJob(config, title, "Waiting in queue")
    db.sql.session.add(entry)
    db.sql.session.commit()
    apply_runner.delay(entry.id)
    return entry.id

def run_audit(config, start=None, end=None):
    parsed_start = util.parsedatestamp(start)
    parsed_end = util.parsedatestamp(end)
    title = ["hc-audit"]
    if parsed_start:
        title += ['from', start]
    if parsed_end:
        title += ['to', end]
    entry = db.AuditJob(config, ' '.join(title), "Waiting in queue")
    if parsed_start:
        entry.start = parsed_start
    if parsed_end:
        entry.end = parsed_end
    db.sql.session.add(entry)
    db.sql.session.commit()
    audit_runner.delay(entry.id)
    return entry.id

def apply_helper(command, entry, s="hc-apply complete against "):
    entry.summary = "Job started"
    db.sql.session.commit()

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for l in iter(p.stdout.readline, ''):
        line = l.strip('\n')
        entry.summary = line

        if line.startswith(s):
            entry.config.expected_hash = line[len(s):]

        db.sql.session.commit()

    p.wait()
    if p.returncode == 0:
        entry.status = 'success'
    else:
        entry.status = 'danger'

    entry.end_date = datetime.datetime.now()
    db.sql.session.commit()

@celery.task()
def apply_runner(entry_id):
    # TODO: lock task such that only one can be run at a time
    entry = db.ApplyJob.query.filter_by(id=entry_id).first()
    repo = util.github_clone_url(entry.config)
    cmd = ['hc-apply', '--vpc-id', entry.config.aws_vpc,
                       repo,
                       entry.config.aws_region,
                       entry.config.aws.key,
                       entry.config.aws.secret]
    if entry.config.expected_hash:
        cmd += ['--expected', entry.config.expected_hash]
    apply_helper(cmd, entry)

def audit_helper(cmd, entry):
    entry.summary = "Audit started"
    db.sql.session.commit()

    def handle_stderr(f, e, q):
        for l in iter(f.stderr.readline, ''):
            q.put(l.strip('\n'))

    def handle_stdout(f, e):
        def unsegment(s):
            r = []
            for i in s:
                if i == ['---']:
                    yield r
                    r = []
                else:
                    r.append(i)
            yield r
        output = f.stdout.read()
        e.csv = output

        data = csv.reader(output.splitlines())
        processed_output = [{
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
        e.json = json.dumps(processed_output)

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    q = queue.Queue()
    t1 = threading.Thread(target=handle_stderr, args=(p, entry, q))
    t2 = threading.Thread(target=handle_stdout, args=(p, entry))
    t1.start()
    t2.start()

    while p.poll() is None:
        while True:
            try:
                entry.summary = q.get_nowait()
            except queue.Empty:
                break
        db.sql.session.commit()
        time.sleep(0.1)

    t1.join()
    t2.join()
    while True:
        try:
            entry.summary = q.get_nowait()
        except queue.Empty:
            break

    entry.status = 'success' if p.returncode == 0 else 'danger'
    entry.end_date = datetime.datetime.now()

    db.sql.session.commit()

@celery.task()
def audit_runner(entry_id):
    entry = db.AuditJob.query.filter_by(id=entry_id).first()
    # TODO: clone first... using github credentials?
    repo = util.github_clone_url(entry.config)
    cmd = ['hc-audit', '--output-webserver', repo, '--region-code', entry.config.aws_region, '--vpc-id', entry.config.aws_vpc, '--aws-access-key-id', entry.config.aws.key, '--aws-secret-access-key', entry.config.aws.secret]
    if entry.start:
        cmd += ['--from-time', entry.start.strftime('%s')]
    if entry.end:
        cmd += ['--to-time', entry.end.strftime('%s')]
    audit_helper(cmd, entry)
