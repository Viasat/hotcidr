from distutils.core import setup

import hotcidr

setup(
    name='HotCIDR',
    version=hotcidr.__version__,
    author=hotcidr.__author__,
    author_email='stephan.kemper@viasat.com',
    packages=['hotcidr', 'hotcidr.test'],
    scripts=['bin/hc-apply', 'bin/hc-audit', 'bin/hc-validate', 'bin/hc-fetch', 'bin/hc-deleteexpired'],
    url='https://github.com/ViaSat/hotcidr',
    license=hotcidr.__license__,
    description="Firewall rule management and automation tools",
    # long_description=open('README.txt').read(),
    install_requires=[
        "GitPython >= 0.3.2.RC1",
        "MySQL-python >= 1.2.5",
        "PyYAML >= 3.10",
        "boto >= 2.28.0",
        "inflect >= 0.2.4",
        "netaddr >= 0.7.11",
        "requests >= 0.14.0",
        "toposort >= 1.0",
    ],
)
