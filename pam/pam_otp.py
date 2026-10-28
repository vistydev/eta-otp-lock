#!/usr/bin/env python3
import os
import pwd
import grp
import traceback
import pyotp
import json

"""
{
    "pingu"  : "JBSWY3DPEHPK3PXP",
    "@users" : "4EF6A46F1BCF2345"
}
"""

## Pam config (common-auth)
## before pam_unix:
# auth sufficient pam_python.so /usr/libexec/pam_otp.py

config_file = "/etc/otp-secrets.json"

# common-auth is shared by every pam service. The pin is meant for logging in
# at the board, it shouldn't replace the password for getting root.
skip_services = ["sudo", "sudo-i", "su", "su-l", "runuser", "runuser-l",
                 "polkit-1", "sshd"]

def pam_sm_authenticate(pamh, flags, argv):
    if pamh.service in skip_services:
        return pamh.PAM_IGNORE

    # fetch username
    try:
        user = pamh.get_user(None)
    except Exception as e:
        return pamh.PAM_AUTH_ERR

    # fetch otp
    if pamh.authtok is None:
        try:
            conv = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Password: "))
            pamh.authtok = conv.resp
        except:
            return pamh.PAM_AUTH_ERR

    # read config
    config = {}
    if not os.path.isfile(config_file):
        return pamh.PAM_AUTH_ERR
    with open(config_file, "r") as f:
        config = json.load(f)


    def check_otp(user):
        otp = pyotp.TOTP(config[user])
        return (otp.now() == pamh.authtok)

    # check otp by group
    for group in grp.getgrall():
        if user in group.gr_mem and f"@{group.gr_name}" in config:
            if check_otp(f"@{group.gr_name}"):
                return pamh.PAM_SUCCESS

    # check otp
    if user in config:
        if check_otp(user):
            return pamh.PAM_SUCCESS

    return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
