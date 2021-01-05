#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
import sys
import yaml

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def populate(filename, config, delimiter):
    fragments = glob.glob(os.path.join('oqs-template', filename, '*.fragment'))
    contents = file_get_contents(filename)

    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]

        if filename == 'README.md':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START -->'.format(delimiter, identifier.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())

        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())

        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]

        contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble
    file_put_contents(filename, contents)

def load_config(include_disabled_sigs=False):
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    if include_disabled_sigs:
        return config
    for sig in config['sigs']:
        sig['variants'] = [variant for variant in sig['variants'] if variant['enable']]
    config['sigs'] = [sig for sig in config['sigs'] if sig['variants']]
    return config

config = load_config()

# update build script
populate('configure.ac', config, '#####')

# add kems
populate('kex.c', config, '/////')
populate('kex.h', config, '/////')
populate('kexoqs.c', config, '/////')
populate('myproposal.h', config, '/////')
populate('regress/unittests/kex/test_kex.c', config, '/////')
populate('ssh2.h', config, '/////')

# add sigs
populate('oqs-utils.h', config, '/////')
populate('pathnames.h', config, '/////')
populate('readconf.c', config, '/////')
populate('servconf.c', config, '/////')
populate('ssh-add.c', config, '/////')
populate('ssh-keygen.c', config, '/////')
populate('ssh-keyscan.c', config, '/////')
populate('ssh-keysign.c', config, '/////')
populate('ssh-oqs.c', config, '/////')
populate('ssh.c', config, '/////')
populate('sshconnect.c', config, '/////')
populate('sshkey.c', config, '/////')
populate('sshkey.h', config, '/////')

# update test suite
populate('oqs-test/test_openssh.py', config, '#####')

config = load_config(include_disabled_sigs=True)
populate('README.md', config, '<!---')
