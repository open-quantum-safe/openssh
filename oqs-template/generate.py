#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
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
        if filename == 'myproposal.h':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START */ \\'.format(delimiter, identifier.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())

        if filename == 'myproposal.h':
            identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END */'.format(delimiter, identifier.upper())
        else:
            identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())

        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]

        contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble

    file_put_contents(filename, contents)

def load_config():
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    return config

config = load_config()

# kexs
populate('kex.c', config, '/////')
populate('kexgen.c', config, '/////')
populate('kexoqs.c', config, '/////')
populate('kexoqsecdh.c', config, '/////')
populate('monitor.c', config, '/////')
populate('sshd.c', config, '/////')
populate('sshconnect2.c', config, '/////')
populate('ssh_api.c', config, '/////')
populate('kex.h', config, '/////')
populate('myproposal.h', config, '/*///')
#populate('ssl/s3_both.cc', config, '/////')
#populate('ssl/ssl_key_share.cc', config, '/////')
#populate('ssl/test/fuzzer.h', config, '/////')
#populate('ssl/test/test_config.cc', config, '/////')

# sigs
#populate('README.md', config, '<!---')

# both
