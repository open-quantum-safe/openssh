#!/bin/bash

set -e

###########
# Run OpenSSH regression tests
###########

TO_INVESTIGATE="integrity \
                keys-command \
                hostkey-agent \
                authinfo \
                principals-command"
SKIPPED_DUE_TO_CERTIFIED_KEYS="agent \
                               cert-hostkey \
                               cert-userkey \
                               cert-file \
                               sshsig \
                               keys-command \
                               hostkey-agent \
                               principals-command"
make tests -e SKIP_LTESTS="${TO_INVESTIGATE} ${SKIPPED_DUE_TO_CERTIFIED_KEYS}"
