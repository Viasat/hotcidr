audit-webapp
============
A simple webapp that runs the auditing tool and formats the output nicely.

Installation
------------
Dependencies:
 - Python 2
 - Flask

Recommended configuration:
 - nginx
 - uwsgi \(with python plugin\)

Sample configuration
--------------------
nginx:

    location /audit/ {
      alias /home/auditor/audit-app/static/;
      index index.html;
    }

    location /audit/job_ {
      alias /home/auditor/audit-app/out/job_;
      index index.html;
    }

    location /audit/create {
      include uwsgi_params;
      uwsgi_pass unix:/tmp/audit-app.sock;
      uwsgi_modifier1 30;
      uwsgi_param SCRIPT_NAME /audit;
    }
uwsgi:

    [uwsgi]
    plugins = python
    socket = /tmp/audit-app.sock
    module = serve:app
    master = true
    processes = 1
    chdir = /home/auditor/audit-app
    close-on-exec = 1
