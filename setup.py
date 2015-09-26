from setuptools import setup, find_packages
import os

PROJECT_DIR = os.path.dirname(__file__)

setup(
    name='noipclient',
    version='0.0.2',
    packages=find_packages(),
    url='http://github.com/acordiner/noipclient',
    license='GPL v2',
    author='Alister Cordiner',
    author_email='alister@cordiner.net',
    description='noip.com Dynamic DNS update client.',
    long_description=open(os.path.join(PROJECT_DIR, 'README.rst')).read(),
    install_requires=[
        'daemonocle==0.8',
    ],
    entry_points={
        'console_scripts': [
            'noipclient = noipclient.noipclient:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Topic :: System :: Networking',
    ],
)
