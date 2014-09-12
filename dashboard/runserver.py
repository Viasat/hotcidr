from hotcidrdash import app
import sys

app.config['LDAP_SEARCH'] = ''
app.config['LDAP_BASE'] = ''
app.config['LDAP_SERVER'] = ''
app.config['LDAP_USER'] = ''
app.config['LDAP_PASS'] = ''

if len(sys.argv) == 2:
    assert(sys.argv[1] == '--debug' or
           sys.argv[1] == '-d')
    app.run(debug=True)
else:
    assert len(sys.argv) == 1
    app.run()
