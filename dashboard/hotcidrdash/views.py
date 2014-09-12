import flask
from hotcidrdash import forms
from hotcidrdash import app
from hotcidrdash import db
from hotcidrdash import util
from hotcidrdash import jobs
import json
import ldap

def get_ldap():
    if not hasattr(flask.g, 'ldap'):
        flask.g.ldap = ldap.initialize(app.config['LDAP_SERVER'])
        flask.g.ldap.simple_bind_s(app.config['LDAP_USER'], app.config['LDAP_PASS'])
    return flask.g.ldap

def render_template(*a, **k):
    c = [(x.slug, x.disp) for x in db.Configuration.query.order_by(db.Configuration.slug).all()]
    return flask.render_template(*a, configs=c, user=flask.g.user, **k)

def login_required(f):
    def decorator(*a, **b):
        if 'user_id' not in flask.session:
            return flask.redirect(flask.url_for('login'))
        if 'maintenance' in flask.session:
            return flask.redirect(flask.url_for('maintenance'))
        return f(*a, **b)
    decorator.__name__ = f.__name__
    return decorator

@app.route('/maintenance')
def maintenance():
    flask.session['maintenance'] = True
    return flask.render_template('maintenance.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if flask.request.method == 'POST':
        try:
            user = app.config['LDAP_SEARCH'].format(username=form.username.data)
            get_ldap().simple_bind_s(user, form.password.data)
            flask.session['user_id'] = form.username.data
            return flask.redirect(flask.url_for('dashboard'))
        except ldap.LDAPError:
            flask.flash('Invalid Login', 'danger')
    return flask.render_template('login.html', form=form)

@app.route('/logout', methods=['GET'])
def logout():
    del flask.session['user_id']
    return flask.redirect(flask.url_for('login'))

@app.before_request
def load_ldap_user():
    flask.g.user = None
    if 'user_id' in flask.session:
        user = flask.session['user_id']
        flask.g.user = {'username': user}
        #f = app.config['LDAP_SEARCH'].format(username=user)
        #results = get_ldap().search_s(base=app.config['LDAP_BASE'],
        #                              scope=ldap.SCOPE_SUBTREE,
        #                              attrlist=['memberOf'],
        #                              filterstr=f)
        #for result in results:
        #    flask.g.user['groups'] = result[1]['memberOf']
        #    break

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', slug='hi')

@app.route('/help')
@login_required
def help():
    return render_template('help.html')

@app.route('/new', methods=['POST', 'GET'])
@login_required
def new_config():
    forms.ConfigForm.reload_presets()
    form = forms.ConfigForm(**flask.request.form)
    if flask.request.method == 'POST' and form.validate():
        if form.aws_preset.data == 'new':
            aws = db.AWS(form.aws.disp.data,
                         form.aws.key.data,
                         form.aws.secret.data)
            db.sql.session.add(aws)
        else:
            assert(form.aws_preset.data.startswith('preset_'))
            aws = db.AWS.query.filter_by(slug=form.aws_preset.data[7:]).first()

        if form.git_preset.data == 'new':
            git = db.GitHub(form.git.disp.data,
                            form.git.url.data,
                            form.git.token.data)
            db.sql.session.add(git)
        else:
            assert(form.git_preset.data.startswith('preset_'))
            git = db.GitHub.query.filter_by(slug=form.git_preset.data[7:]).first()
        conf = db.Configuration(form.disp.data,
                                aws,
                                form.aws_region.data,
                                form.aws_vpc.data,
                                git,
                                form.git_repo.data,
                                form.cron.data)
        jobs.schedule_apply(conf)
        db.sql.session.add(conf)
        db.sql.session.commit()
        return flask.redirect(flask.url_for('view_config', slug=conf.slug))
    else:
        return render_template('edit_config.html', form=form)

@app.route('/config/<slug>/edit', methods=['POST', 'GET'])
@login_required
def edit_config(slug):
    conf = db.Configuration.query.filter_by(slug=slug).first_or_404()
    forms.ConfigForm.reload_presets()
    form = forms.ConfigForm(data={
        'disp': conf.disp,
        'aws_preset': 'preset_' + conf.aws.slug if hasattr(conf.aws, 'slug') else 'new',
        'aws_region': conf.aws_region,
        'aws_vpc': conf.aws_vpc,
        'git_preset': 'preset_' + conf.git.slug if hasattr(conf.git, 'slug') else 'new',
        'git_repo': conf.git_repo,
        'cron': conf.cron,
    })
    if flask.request.method == 'POST':
        if flask.request.form['action'] == 'delete':
            db.sql.session.delete(conf)
            db.sql.session.commit()
            flask.flash('Deleted', 'success')
            return flask.redirect(flask.url_for('dashboard'))
        elif form.validate():
            if form.aws_preset.data == 'new':
                aws = db.AWS(form.aws.disp.data,
                             form.aws.key.data,
                             form.aws.secret.data)
                db.sql.session.add(aws)
            else:
                assert(form.aws_preset.data.startswith('preset_'))
                aws = db.AWS.query.filter_by(slug=form.aws_preset.data[7:]).first()

            if form.git_preset.data == 'new':
                git = db.GitHub(form.git.disp.data,
                                form.git.url.data,
                                form.git.token.data)
                db.sql.session.add(git)
            else:
                assert(form.git_preset.data.startswith('preset_'))
                git = db.GitHub.query.filter_by(slug=form.git_preset.data[7:]).first()

            slug = util.slugify(form.disp.data)
            conf.disp = form.disp.data
            conf.slug = slug
            conf.aws = aws
            conf.aws_region = form.aws_region.data
            conf.aws_vpc = form.aws_vpc.data
            conf.git = git
            conf.git_repo = form.git_repo.data
            conf.cron = form.cron.data
            jobs.schedule_apply(conf)
            db.sql.session.commit()
            flask.flash('Saved', 'success')
            return flask.redirect(flask.url_for('view_config', slug=slug))
    return render_template('edit_config.html', disp=conf.disp, slug=conf.slug, form=form)

@app.route('/config/<slug>', methods=['POST', 'GET'])
@login_required
def view_config(slug):
    conf = db.Configuration.query.filter_by(slug=slug).first_or_404()
    if flask.request.method == 'POST':
        if flask.request.form['action'] == 'apply':
            jobs.run_apply(conf, "Manual hc-apply")
            flask.flash('Job queued', 'success')
        else:
            flask.flash('Unknown action', 'danger')
    j = db.ApplyJob.query.filter_by(config_id=conf.id).order_by(db.ApplyJob.start_date.desc()).limit(5)
    open_issues = util.github_issue_count(conf)
    webpage_url = util.github_get_webpage(conf)
    if not webpage_url:
        flask.flash('Could not find %s' % conf.git_repo, 'danger')
    return render_template('view_config.html', conf=conf,
                                               jobs=j,
                                               open_issues=open_issues,
                                               webpage_url=webpage_url)

@app.route('/config/<slug>/apply', methods=['GET'])
def apply(slug):
    # TODO: Add authentication to this endpoint
    conf = db.Configuration.query.filter_by(slug=slug).first_or_404()
    jobs.run_apply(conf, "Automatic hc-apply")
    return "Success"

@app.route('/config/<slug>/apply_out/<job_id>')
@login_required
def view_apply_output(slug, job_id):
    job = db.ApplyJob.query.filter_by(id=job_id).first_or_404()
    conf = job.config
    if conf.slug != slug:
        flask.abort(404)
    return render_template('view_apply_output.html', job=job, conf=conf)

@app.route('/config/<slug>/apply/<int:page>')
@login_required
def view_old_apply(slug, page):
    conf = db.Configuration.query.filter_by(slug=slug).first_or_404()
    j = db.ApplyJob.query.filter_by(config_id=conf.id).order_by(db.ApplyJob.start_date.desc()).paginate(page)
    return render_template('view_old_apply.html', conf=conf, results=j)

@app.route('/config/<slug>/audit', methods=['POST', 'GET'])
@login_required
def create_audit(slug):
    conf = db.Configuration.query.filter_by(slug=slug).first_or_404()
    form = forms.AuditForm()
    if flask.request.method == 'POST':
        job_id = jobs.run_audit(conf, start=form.start.data, end=form.end.data)
        return flask.redirect(flask.url_for('view_audit', slug=slug, job_id=job_id))
    else:
        j = db.AuditJob.query.filter_by(config_id=conf.id).order_by(db.AuditJob.start_date.desc()).limit(5)
        return render_template('create_audit.html', conf=conf, form=form, jobs=j)

@app.route('/config/<slug>/audit/<int:page>')
@login_required
def view_old_audit(slug, page):
    conf = db.Configuration.query.filter_by(slug=slug).first_or_404()
    j = db.AuditJob.query.filter_by(config_id=conf.id).order_by(db.AuditJob.start_date.desc()).paginate(page)
    return render_template('view_old_audit.html', conf=conf, results=j)

@app.route('/config/<slug>/audit_out/<job_id>')
@login_required
def view_audit(slug, job_id):
    job = db.AuditJob.query.filter_by(id=job_id).first_or_404()
    conf = job.config
    if conf.slug != slug:
        flask.abort(404)
    try:
        e = json.loads(str(job.json))
    except ValueError:
        e = []
    return render_template('view_audit.html', job=job, conf=conf, entries=e)

@app.route('/config/<slug>/audit/<job_id>/status')
@login_required
def view_audit_status(slug, job_id):
    job = db.AuditJob.query.filter_by(id=job_id).first_or_404()
    conf = job.config
    if conf.slug != slug:
        flask.abort(404)
    r = dict(zip(('progress', 'status'), util.auditerr(job.summary)))
    r['done'] = True if job.end_date else False
    return json.dumps(r)

@app.route('/config/<slug>/audit_out/<job_id>/download')
@login_required
def download_audit(slug, job_id):
    job = db.AuditJob.query.filter_by(id=job_id).first_or_404()
    if job.config.slug != slug:
        flask.abort(404)
    r = flask.make_response(job.csv)
    r.headers['Content-Disposition'] = "attachment; filename=audit_%s.csv" % slug
    return r

@app.route('/git/<slug>')
@login_required
def view_git(slug):
    git = db.GitHub.query.filter_by(slug=slug).first_or_404()
    return render_template('view_github.html', git=git)

@app.route('/git/<slug>/edit', methods=['POST', 'GET'])
@login_required
def edit_git(slug):
    git = db.GitHub.query.filter_by(slug=slug).first_or_404()
    form = forms.GitHubForm(disp=git.disp, url=git.url, token=git.token)
    if flask.request.method == 'POST':
        if flask.request.form['action'] == 'delete':
            msg = util.usedby(git.configurations)
            if msg:
                flask.flash(msg, 'danger')
                return flask.redirect(flask.url_for('edit_git', slug=slug))
            else:
                db.sql.session.delete(git)
                db.sql.session.commit()
                flask.flash('Deleted', 'success')
                return flask.redirect(flask.url_for('presets'))
        elif form.validate():
            slug = util.slugify(form.disp.data)
            git.disp = form.disp.data
            git.slug = slug
            git.url = form.url.data
            git.token = form.token.data
            db.sql.session.commit()
            flask.flash("Saved", 'success')
            return flask.redirect(flask.url_for('edit_git', slug=slug))
    return render_template('edit_github.html', disp=git.disp, form=form)

@app.route('/aws/<slug>')
@login_required
def view_aws(slug):
    aws = db.AWS.query.filter_by(slug=slug).first_or_404()
    return render_template('view_aws.html', aws=aws)

@app.route('/aws/<slug>/edit', methods=['POST', 'GET'])
@login_required
def edit_aws(slug):
    aws = db.AWS.query.filter_by(slug=slug).first_or_404()
    form = forms.AWSForm(disp=aws.disp, key=aws.key, secret=aws.secret)
    if flask.request.method == 'POST':
        if flask.request.form['action'] == 'delete':
            msg = util.usedby(aws.configurations)
            if msg:
                flask.flash(msg, 'danger')
                return flask.redirect(flask.url_for('edit_aws', slug=slug))
            else:
                db.sql.session.delete(aws)
                db.sql.session.commit()
                flask.flash('Deleted', 'success')
                return flask.redirect(flask.url_for('presets'))
        elif form.validate():
            slug = util.slugify(form.disp.data)
            aws.disp = form.disp.data
            aws.slug = slug
            aws.key = form.key.data
            aws.secret = form.secret.data
            db.sql.session.commit()
            flask.flash("Saved", 'success')
            return flask.redirect(flask.url_for('edit_aws', slug=slug))
    return render_template('edit_aws.html', disp=aws.disp, form=form)

@app.route('/presets')
@login_required
def presets():
    aws = [(x.slug, x.disp) for x in db.AWS.query.order_by(db.AWS.slug).all()]
    git = [(x.slug, x.disp) for x in db.GitHub.query.order_by(db.GitHub.slug).all()]
    return render_template('presets.html', aws=aws, git=git)

@app.route('/reload')
@login_required
def reload():
    pass
