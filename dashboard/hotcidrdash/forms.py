from hotcidrdash import db
from flask_wtf import Form
import wtforms

class BootstrapTextField(wtforms.widgets.TextInput):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        kwargs.setdefault('type', 'text')
        kwargs.setdefault('class', 'form-control')
        kwargs.setdefault('value', field._value())
        kwargs.setdefault('name', field.name)
        return wtforms.widgets.HTMLString('<div class="form-group">\n%s\n<input %s>\n</div>''' %
                (field.label, wtforms.widgets.html_params(**kwargs)))

class BootstrapPasswordField(wtforms.widgets.PasswordInput, BootstrapTextField):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('type', 'password')
        return super(BootstrapPasswordField, self).__call__(field, **kwargs)

class BootstrapDateField(BootstrapTextField):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('class', 'form-control datepicker')
        return super(BootstrapDateField, self).__call__(field, **kwargs)


class BootstrapSelectBox(wtforms.widgets.Select):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('class', 'form-control')
        return '<div class="form-group">%s</div>' % super(BootstrapSelectBox, self).__call__(field, **kwargs)


class BootstrapWell(wtforms.widgets.ListWidget):
    def __init__(self):
        pass

    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        kwargs.setdefault('class', 'well')
        return wtforms.widgets.HTMLString('<div %s>%s</div>' % (
                wtforms.widgets.html_params(**kwargs),
                '\n'.join(subfield() for subfield in field)))

class StringField(wtforms.StringField):
    def __init__(self, *a, **k):
        k.setdefault('widget', BootstrapTextField())
        super(StringField, self).__init__(*a, **k)


class FormField(wtforms.FormField):
    def __init__(self, *a, **k):
        k.setdefault('widget', BootstrapWell())
        super(FormField, self).__init__(*a, **k)


class SelectField(wtforms.SelectField):
    def __init__(self, *a, **k):
        k.setdefault('widget', BootstrapSelectBox())
        super(SelectField, self).__init__(*a, **k)


class PresetField(SelectField):
    def __init__(self, *a, **k):
        k['choices'] = [('new', 'New Preset')] + [('preset_' + x, y) for (x, y) in k['choices']]
        super(PresetField, self).__init__(*a, **k)


class LoginForm(Form):
    username = StringField('Username')
    password = StringField('Password', widget=BootstrapPasswordField())


class AWSForm(Form):
    disp = StringField('Name')
    key = StringField('API Key')
    secret = StringField('API Secret')


class GitHubForm(Form):
    disp = StringField('Name')
    url = StringField('API URL')
    token = StringField('API Token')


class ConfigForm(Form):
    disp = StringField('Configuration Name')
    aws = FormField(AWSForm)
    aws_region = StringField('Region')
    aws_vpc = StringField('VPC')
    git = FormField(GitHubForm)
    git_repo = StringField('Repository Name')
    cron = StringField('Cron')

    @staticmethod
    def reload_presets():
        setattr(ConfigForm, 'aws_preset', PresetField('AWS Preset', choices=[(x.slug, x.disp) for x in db.AWS.query.all()]))
        setattr(ConfigForm, 'git_preset', PresetField('GitHub Preset', choices=[(x.slug, x.disp) for x in db.GitHub.query.all()]))


class AuditForm(Form):
    start = StringField('Start Date', widget=BootstrapDateField())
    end = StringField('End Date', widget=BootstrapDateField())
