#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.algos import wiener


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Wiener's attack"""
        pq = wiener(publickey.n, publickey.e, progress)
        if pq is None:
            self.logger.warning("[*] Cracking failed...")
        else:
            publickey.p, publickey.q = pq
            priv_key = PrivateKey(
                int(publickey.p),
                int(publickey.q),
                int(publickey.e),
                int(publickey.n),
            )

            print("[*] Cracking successful!")
            return priv_key, None
        return None, None

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
