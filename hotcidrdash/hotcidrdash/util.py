import flask.ext.assets
from hotcidrdash import app
import requests
import time
import datetime

assets = flask.ext.assets.Environment(app)


def auditerr(s):
    prog, _, stat = s.partition('% ')
    try:
        if 0 <= int(prog) <= 100:
            prog = int(prog)
        else:
            raise ValueError
    except ValueError:
        return (0, s)
    return (prog, stat)
app.jinja_env.filters['auditprog'] = lambda s: auditerr(s)[0]
app.jinja_env.filters['auditstat'] = lambda s: auditerr(s)[1]

def parsedatestamp(s):
    try:
        return datetime.date.fromtimestamp(time.mktime(time.strptime(s, '%Y-%m-%d')))
    except ValueError:
        return None

def slugify(s, allowed_chars=set('abcdefghijklmnopqrstuvwxyz1234567890-')):
    r = ''.join([c for c in s.lower().replace(' ', '-') if c in allowed_chars])
    if not len(r):
        r = 'blank'
    return r

def usedby(x, m=2):
    c = x.count()
    if c:
        r = ["Preset is used by "]
        if c - m <= 1:
            r.append(", ".join(i.disp for i in x.all()))
        else:
            r.append(", ".join(i.disp for i in x.limit(m).all()))
            r.append(" and %d others" % (c - m))
        return ''.join(r)

class GitHub(object):
    def __init__(self, api_url=None, token=None):
        if not api_url:
            self.api_url = 'https://api.github.com/v3'
        else:
            self.api_url = api_url.rstrip('/')

    def __getattr__(self, x):
        return getattr(GitHubAPICall(self), x)

    def __getitem__(self, x):
        return GitHubAPICall(self)[x]

    def send(self, method, url, token=None, **kwargs):
        if token:
            kwargs['auth'] = ('token', token)
        kwargs.setdefault('headers', {'accept': 'application/vnd.github.v3+json'})

        try:
            r = requests.request(method, url, **kwargs)
            return r.json()
        except requests.exceptions.MissingSchema:
            return None

class GitHubAPICall(object):
    def __init__(self, github):
        self._github = github
        self.url = github.api_url

    def __getattr__(self, x, params=None, headers=None):
        if x in ('get', 'post', 'head', 'put', 'delete', 'patch'):
            def inner(params=None, headers=None):
                return self._github.send(x, self.url, params=params, headers=headers)
            return inner
        else:
            self.url += '/' + x
            return self

    def __getitem__(self, x):
        return getattr(self, x)

    def __repr__(self):
        return 'GitHub API Call: %s' % self.url

def request_cache(f):
    def decorator(*a, **k):
        q = str(list(a) + sorted(list(k.items())))
        if not hasattr(flask.request, 'cache'):
            flask.request.cache = {}

        if q not in flask.request.cache:
            flask.request.cache[q] = f(*a, **k)
        return flask.request.cache[q]
    return decorator

#@request_cache
def github_repo(config):
    git = config.git
    r = GitHub(git.url, git.token).repos[config.git_repo].get()
    return r

def github_repo_attr(config, attr):
    r = github_repo(config)
    if r and attr in r:
        return r[attr]

github_issue_count = lambda config: github_repo_attr(config, 'open_issues')
github_clone_url = lambda config: github_repo_attr(config, 'clone_url')
github_get_webpage = lambda config: github_repo_attr(config, 'html_url')
