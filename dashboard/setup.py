from distutils.core import setup

setup(
    name='HotCIDR Dashboard',
    version='0.1.0',
    author='ViaSat',
    author_email='stephan.kemper@viasat.com',
    packages=['hotcidrdash'],
    license='LICENSE.txt',
    description="Web Dashboard for HotCIDR",
    install_requires=[
        "Flask >= 0.10.1",
        "Flask-Assets >= 0.9",
        "Flask-SQLAlchemy >= 1.0",
        "Flask-WTF >= 0.9.5",
        "HotCIDR >= 0.1.0",
        "humanize >= 0.5",
        "redis >= 2.9.1",
        "requests >= 2.3.0",
    ],
)
