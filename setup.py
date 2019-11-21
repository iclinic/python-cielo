# coding: utf-8
import os
import re
from setuptools import Command, find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

version = '0.0.0'
with open(os.path.join(here, 'CHANGES.txt')) as changes:
    for line in changes:
        version = line.strip()
        if re.search(r'^[0-9]+\.[0-9]+(\.[0-9]+)?$', version):
            break

f = open(os.path.join(os.path.dirname(__file__), 'README.rst'))
readme = f.read()
f.close()


class VersionCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print(version)


setup(
    name='python-cielo',
    version=version,
    description='python-cielo is a lightweight lib for making payments over the Cielo webservice (Brazil)',
    long_description=readme,
    classifiers=[
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='cielo e-commerce',
    author='Renato Pedigoni',
    author_email='renatopedigoni@gmail.com',
    url='http://github.com/rpedigoni/python-cielo',
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=['requests'],
    cmdclass={'version': VersionCommand},
)
