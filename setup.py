import os
from setuptools import setup, find_packages

def read(fname):
  return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "MeTH",
    version = "0.1",
    author = "MrZ3r0",
    author_email = "TheDeathWing@protonmail.com",
    description = "Multi Account Credentials Checker",
    license = "BSD",
    url = "https://thedeathwing.tk",
    download_url = "https://github.com/TheDeathWing/MeTH",
    packages=find_packages(),
    long_description=read('README.md'),
    include_package_data=True,
    scripts=('MeTH.py',),
    entry_points={},
    install_requires = [
      'requests',
      'urllib',
      'BeautifulSoup4',
      'cfscrape',
      'decorator',
      'pathlib',
      'future'
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "Topic :: Security",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: BSD License",
    ],
)