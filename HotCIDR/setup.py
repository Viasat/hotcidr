from distutils.core import setup

setup(
    name='HotCIDR',
    version='0.1.0',
    author='ViaSat',
    author_email='stephan.kemper@viasat.com',
    packages=['hotcidr', 'hotcidr.test'],
    scripts=['bin/hc-apply', 'bin/hc-audit', 'bin/hc-validate', 'bin/hc-fetch', 'bin/hc-deleteexpired','bin/hc-setupall'],
    #url='http://pypi.python.org/pypi/HotCIDR',
    license='LICENSE.txt',
    description="Firewall rule management and automation tools",
    long_description=open('README.txt').read(),
    install_requires=[
        "GitPython >= 0.1.7",
        "MySQL-python >= 1.2.5",
        "PyYAML >= 3.10",
        "boto >= 2.31.1",
        "inflect >= 0.2.4",
        "netaddr >= 0.7.12",
        "requests >= 0.14.0",
        "toposort >= 1.1",
    ],
)
