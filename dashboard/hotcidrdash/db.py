import datetime
import humanize
from flask.ext.sqlalchemy import SQLAlchemy
from hotcidrdash import app
from hotcidrdash import util

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cp.db'
sql = SQLAlchemy(app)

class AWS(sql.Model):
    id = sql.Column(sql.Integer, primary_key=True)
    slug = sql.Column(sql.String(80), unique=True)
    disp = sql.Column(sql.Text)

    key = sql.Column(sql.CHAR(20))
    secret = sql.Column(sql.CHAR(40))

    def __init__(self, disp, key, secret, slug=None):
        self.disp = disp
        self.key = key
        self.secret = secret

        if slug:
            self.slug = slug
        else:
            self.slug = util.slugify(disp)

    def __repr__(self):
        return '<AWS %s>' % self.slug


class GitHub(sql.Model):
    id = sql.Column(sql.Integer, primary_key=True)
    slug = sql.Column(sql.String(80), unique=True)
    disp = sql.Column(sql.Text)

    url = sql.Column(sql.String(80))
    token = sql.Column(sql.CHAR(40))

    def __init__(self, disp, url, token, slug=None):
        self.disp = disp
        self.url = url
        self.token = token

        if slug:
            self.slug = slug
        else:
            self.slug = util.slugify(disp)

    def __repr__(self):
        return '<GitHub %s>' % self.slug


class Configuration(sql.Model):
    id = sql.Column(sql.Integer, primary_key=True)
    slug = sql.Column(sql.String(80), unique=True)
    disp = sql.Column(sql.Text)

    aws_id = sql.Column(sql.Integer, sql.ForeignKey(AWS.id))
    aws = sql.relationship('AWS',
            backref=sql.backref('configurations', lazy='dynamic'))
    git_id = sql.Column(sql.Integer, sql.ForeignKey(GitHub.id))
    git = sql.relationship('GitHub',
            backref=sql.backref('configurations', lazy='dynamic'))
    aws_vpc = sql.Column(sql.String(80))
    git_repo = sql.Column(sql.String(80))
    aws_region = sql.Column(sql.String(80))
    expected_hash = sql.Column(sql.String(40))
    cron = sql.Column(sql.Text)

    def __init__(self, disp, aws, aws_region, aws_vpc, git, git_repo, cron, slug=None):
        self.disp = disp
        self.aws = aws
        self.aws_vpc = aws_vpc
        self.aws_region = aws_region
        self.git = git
        self.git_repo = git_repo
        self.cron = cron

        if slug:
            self.slug = slug
        else:
            self.slug = util.slugify(disp)

    def __repr__(self):
        return '<Configuration %s>' % self.slug


class ApplyJob(sql.Model):
    id = sql.Column(sql.Integer, primary_key=True)
    config_id = sql.Column(sql.Integer, sql.ForeignKey(Configuration.id))
    config = sql.relationship('Configuration',
            backref=sql.backref('apply_outputs', lazy='dynamic'))

    title = sql.Column(sql.Text)

    output = sql.Column(sql.Text)

    status = sql.Column(sql.Enum("success", "warning", "danger"))

    start_date = sql.Column(sql.DateTime)
    end_date = sql.Column(sql.DateTime)

    def __init__(self, config, title, summary):
        self.config = config
        self.title = title
        self.output = summary
        self.start_date = datetime.datetime.now()
        self.end_date = None

    def __repr__(self):
        return '<Apply Output for %s>' % self.config

    @property
    def timeago(self):
        return humanize.naturaltime(self.start_date)

    @property
    def summary(self):
        return self.output.splitlines()[-1]

    @summary.setter
    def summary(self, v):
        self.output = str(self.output) + '\n' + v


class AuditJob(sql.Model):
    id = sql.Column(sql.Integer, primary_key=True)
    config_id = sql.Column(sql.Integer, sql.ForeignKey(Configuration.id))
    config = sql.relationship('Configuration',
            backref=sql.backref('audit_outputs', lazy='dynamic'))

    start = sql.Column(sql.DateTime)
    end = sql.Column(sql.DateTime)

    title = sql.Column(sql.Text)

    json = sql.Column(sql.Text)
    csv = sql.Column(sql.Text)
    log = sql.Column(sql.Text)

    status = sql.Column(sql.Enum("success", "warning", "danger"))

    start_date = sql.Column(sql.DateTime)
    end_date = sql.Column(sql.DateTime)

    def __init__(self, config, title, summary):
        self.config = config
        self.title = title
        self.log = summary
        self.start_date = datetime.datetime.now()
        self.end_date = None

    def __repr__(self):
        return '<Audit for %s>' % self.config

    @property
    def timeago(self):
        return humanize.naturaltime(self.start_date)

    @property
    def summary(self):
        return self.log.splitlines()[-1]

    @summary.setter
    def summary(self, v):
        self.log = str(self.log) + "\n" + v
