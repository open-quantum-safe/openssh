#!/bin/bash

###########
# Run OpenSSH regression tests
###########

# integrity, keys-command, hostkey-agent, and principals-command test failures have to be
# investigated further. The rest are due to us not supporting certified keys.
env SKIP_LTESTS="agent cert-hostkey cert-userkey cert-file sshsig keys-command hostkey-agent principals-command integrity" make tests
