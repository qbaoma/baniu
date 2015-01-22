import sys
import os
from setuptools import setup, find_packages

VERSION = '0.1.5'

if sys.argv[-1] == 'test':
    test_requirements = [
        'pytest',
        'flake8',
        'coverage',
        'pytest-cov'
    ]
    try:
        modules = map(__import__, test_requirements)
    except ImportError as e:
        err_msg = e.message.replace("No module named ", "")
        msg = "%s is not installed. Install your test requirments." % err_msg
        raise ImportError(msg)
    os.system('py.test --cov=baniu')
    sys.exit()

if sys.argv[-1] == 'doc':
    requirements = [
        'sphinx',
    ]
    try:
        modules = map(__import__, requirements)
    except ImportError as e:
        err_msg = e.message.replace("No module named ", "")
        msg = "%s is not installed. Install your test requirments." % err_msg
        raise ImportError(msg)
    os.system('sphinx-apidoc -F -f -o doc baniu')
    sys.exit()

setup(
    name='baniu',
    version=VERSION,
    author='xiaoyu',
    author_email='xiaokong1937@gmail.com',
    description=('Third-party Qiniu Resource SDK'),
    install_requires=['requests'],
    platforms='any',
    url="http://github.com/xkong/baniu",
    packages=find_packages(exclude=('tests', 'doc')),
    zip_safe=False,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
