#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.crypto_wrapper import RSA
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Use boneh durfee method, should return a d value, else returns 0
        only works if the sageworks() function returned True
        many of these problems will be solved by the wiener attack module but perhaps some will fall through to here
        """
        try:
            sageresult = int(
                subprocess.check_output(
                    [
                        "sage",
                        f"{rootpath}/sage/boneh_durfee.sage",
                        str(publickey.n),
                        str(publickey.e),
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"Error occurred while running Sage: {e}")
            return (None, None)
        
        if sageresult > 0:
            tmp_priv = RSA.construct((int(publickey.n), int(publickey.e), sageresult))
            publickey.p = tmp_priv.p
            publickey.q = tmp_priv.q
            privatekey = PrivateKey(
                p=int(publickey.p),
                q=int(publickey.q),
                e=int(publickey.e),
                n=int(publickey.n),
            )
            return (privatekey, None)
        
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIICLTANBgkqhkiG9w0BAQEFAAOCAhoAMIICFQKCAQcAk9+F9+kcsVi/wXNRlW9U
DdSjjsIbjy7M7hrWJCfnlbHri/wgw/YKOw2nfB9VAPSjtPXlqR+05JDpD7V5O2cQ
mgbafV8cnspgWS6SLGOqk4CXp4beMmf6J9WvYYJFodPj5uzi3eoBTa4TywdYnTml
Zeqsl2Z5F8tTKjrCZAAwIRYK9qTB0pQT2UkcNZFitWnJRjg5hdl0SsIbkqQ9N+0+
IGQ62LggOwS+cZRQ5g4AfQ9XccgP0nqSm3GXoC65OpO9UG1ulqrvrK7W9vhNZ4wB
jtr0HsignqSgnoJdWA4HuWOIDi7bi2Gs2G6TldBJTUVd5XGxQPZlNVnqF9jXC4Dd
HZ3uzuRKAQKCAQZNcQEByuAwqv2d/qz/cfcyabbHKbrp5G4mKk3193qT2hSd0Qsq
30zeVwaEmaU/VuV/VgpIUJKppfGIQoLRAegUkH0ahmossrYXtu3urpLwVzw8RUmt
+m52P31hh9WYkuPvwDRNvras7lJ0Tc5AypW6B8hjdEBrVLS9McJkOcHzeMktyP/p
oVEVYQ0nEYHKc1ASOhD5mc1S23f5iq1HWaGD86zRzSJOU5Uia1PIhW7DeBp+4EEL
bi6ck4fstVI5bBuitFr0+7QvZX3Aym/9UUacGR1JLTbm0mpyWF/znxwhnQmf84M2
RRmeR/ZvE7iGMeSoBGu1dGYOApKK4C1BT7f0IMOPY3/z
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result
