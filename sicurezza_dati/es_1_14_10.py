import base64
import json
import os
import hmac
import secrets
from dataclasses import dataclass
from typing import Dict, Any, Optional

try:
    from cryptography.fernet import Fernet
    _HAS_CRYPTO = True
except Eception:
    _HAS_CRYPTO = False

import hashlib

# funzioni di utilità per le operazioni di sicurezza
def _rand_bytes(n: int = 16) -> bytes:
    return secrets.token_bytes(n)

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def _ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

# derivazione di una chiave simmetrica dalla passphrase usando scrypt (parametri sicuri e non eccessivamente pesanti)
def _derive_key_from_passphrase(passphrase: str, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1, dklen: int = 32) -> bytes:
    return hashlib.scrypt(passphrase.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)

# funzione per l'hashing delle password alla registrazione della relativa verifica di autenticazione
def _hash_password_scrypt(password: str, n: int = 2**14, r: int = 8, p: int = 1, dklen: int = 64) -> Dict[str, Any]:
    salt = _rand_bytes(16)
    dk = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return {
        'algo': 'scrypt',
        'n': n,
        'r': r,
        'p': p,
        'dklen': dklen,
        'salt_b64': _b64e(salt),
        'hash_b64': _b64e(dk)
    }

def _verify_password_scrypt(rec: Dict[str, Any], password: str) -> bool:
    salt = _b64d(rec['salt_b64'])
    expected = _b64d(rec['hash_b64'])
    n, r, p, dklen = int(rec['n']), int(rec['r']), int(rec['p']), int(rec['dklen'])
    dk = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return _ct_eq(dk, expected)

@dataclass
class PasswordStore:
    path: str
    mode: str = 'hashed' # 'simple' | 'hashed' | 'encrypted'
    master_passphrase: Optional[str] = None # richiesto solo se mode = "encrypted"

    def __post_init__(self):
        if self.mode not in ('simple', 'hashed', 'encrypted'):
            raise ValueError("mode must be 'simple', 'hashed', or 'encrypted'")

        self._data: Dict[str, Any] = {"mode": self.mode, "users": {}}

        # carica se esiste
        if os.path.exists(self.path):
            self._load()
            # coerenza modalità
            if self._data['mode'] != self.mode:
                raise ValueError(f"File mode '{self._data['mode']}' does not match specified mode '{self.mode}'")

        # setup per encrypted
        if self.mode == 'encrypted':
            if not _HAS_CRYPTO:
                raise RuntimeError("cryptography package is required for encrypted mode, execute 'pip install cryptography'")

            if "kdf" not in self._data:
                # inizializza salt per la derivazione della chiave

                kdf_salt = _rand_bytes(16)
                self._data['kdf'] = {
                    "salt_b64": _b64e(kdf_salt),
                    "n": 2**14,
                    "r": 8,
                    "p": 1,
                    "dklen": 32
                }
                self._save()

            if not self.master_passphrase:
                raise ValueError("master_passphrase is required for encrypted mode")
            self._fernet = self._make_fernet(self.master_passphrase)

    # ----------------------- IO -----------------------
    def _load(self):
        with open(self.path, 'r', encoding='utf-8') as f:
            self._data = json.load(f)

    def _save(self):
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    # ----------------------- Fernet Helper -----------------------
    def _make_fernet(self, passphrase: str) -> Fernet:
        kdf = self._data['kdf']
        salt = _b64d(kdf['salt_b64'])
        key = _derive_key_from_passphrase(passphrase, salt, n=int(kdf['n']), r=int(kdf['r']), p=int(kdf['p']), dklen=int(kdf['dklen']))
        # Fernet vuole una key base64 urlsafe da 32 bytes
        fkey = base64.urlsafe_b64encode(key)
        return Fernet(fkey)

    # ----------------------- API Utente -----------------------
    def add_user(self, username: str, password: str, overwrite: bool = False):
        users = self._data['users']
        if(username in users) and not overwrite:
            raise ValueError(f"User '{username}' already exists (use overwrite=True to replace)")

        if self.mode == 'simple':
            users[username] = {'type': 'simple', 'password': password}

        elif self.mode == 'encrypted':
            token = self._fernet.encrypt(password.encode('utf-8'))
            users[username] = {'type': 'encrypted', 'password_b64': _b64e(token)}

        elif self.mode == 'hashed':
            rec = _hash_password_scrypt(password)
            rec['type'] = 'hashed'
            users[username] = rec

        else:
            raise RuntimeError("Invalid mode")

        self._save()

    def verify_user(self, username: str, password: str) -> bool:
        user = self._data['users'].get(username)
        if not user:
            return False

        t = user.get('type')
        if t == 'simple':
            return hmac.compare_digest(user['password'], password)

        elif t == "encrypted":
            token = _b64d(user["password_b64"])
            try:
                clear = self._fernet.decrypt(token)
            except Exception:
                return False
            return _ct_eq(clear, password.encode('utf-8'))

        elif t == "hashed":
            return _verify_password_scrypt(user, password)

        else:
            return False

    def change_password(self, username: str, new_password: str):
        if username not in self._data['users']:
            raise ValueError(f"User '{username}' does not exist")
        # riutilizza add_user con overwrite
        self.add_user(username, new_password, overwrite=True)

    def delete_user(self, username: str):
        if username not in self._data['users']:
            raise ValueError(f"User '{username}' does not exist")
        del self._data['users'][username]
        self._save()

    def list_users(self):
        return sorted(self._data['users'].keys())

    # utility di migrazione tra modalità
    def migrate_to(self, new_mode: str, master_passphrase: Optional[str] = None):
        """
        Migra lo store alla nuova modalità. Richiede la password corrente di ogni utente
        solo se si passa da hashed -> encrypted / simple (non essendo invertibile).
        per una demo semplice: invalida le password e richiede reset all'utente.
        """

        if new_mode not in ('simple', 'hashed', 'encrypted'):
            raise ValueError("new_mode must be 'simple', 'hashed', or 'encrypted'")

        # per semplicità azzeriamo le password e chiediamo reset (più sicuro)
        useernames = list(self._data['users'].keys())
        self.mode = new_mode
        self._data = {"mode": self.mode, "users": {}}

        if new_mode == 'encrypted':
            if not _HAS_CRYPTO:
                raise RuntimeError("cryptography package is required for encrypted mode, execute 'pip install cryptography'")
            if not master_passphrase:
                raise ValueError("master_passphrase is required for encrypted mode")
            kdf_salt = _rand_bytes(16)
            self._data['kdf'] = {
                "salt_b64": _b64e(kdf_salt),
                "n": 2**14,
                "r": 8,
                "p": 1,
                "dklen": 32
            }
            self._fernet = self._make_fernet(master_passphrase)

        for u in usernames:
            # mettiamo placeholder che forza il reset
            self._data['users'][u] = {'type': 'reset_required'}
        self._save()

    def needs_reset(self, username: str) -> bool:
        rec = self._data['users'].get(username)
        return rec is not None and rec.get('type') == 'reset_required'

# demo di utilizzo
if __name__ == '__main__':

    demo_path = "vault_hashed.json"
    store = PasswordStore(demo_path, mode='hashed')

    if 'alice' not in store.list_users():
        store.add_user('alice', 'wonderland123')
        print("User 'alice' added.")

    print("Current users in hashed store:", store.list_users())
    print("Verifying 'alice' with correct password:", store.verify_user('alice', 'wonderland123'))
    print("Verifying 'alice' with wrong password:", store.verify_user('alice', 'wrongpassword'))
    store.change_password('alice', 'newpassword456')
    print("Password for 'alice' changed.")
    print("Verifying 'alice' with old password:", store.verify_user('alice', 'wonderland123'))
    print("Verifying 'alice' with new password:", store.verify_user('alice', 'newpassword456'))


    demo_path_enc = "vault_encrypted.json"
    store_enc = PasswordStore(demo_path_enc, mode='encrypted', master_passphrase='supersecret')

    if 'bob' not in store_enc.list_users():
        store_enc.add_user('bob', 'builder789')
        print("User 'bob' added.")

    print("Current users in encrypted store:", store_enc.list_users())
    print("Verifying 'bob' with correct password:", store_enc.verify_user('bob', 'builder789'))
    print("Verifying 'bob' with wrong password:", store_enc.verify_user('bob', 'wrongpassword'))
    store_enc.change_password('bob', 'newbuilder012')
    print("Password for 'bob' changed.")
    print("Verifying 'bob' with old password:", store_enc.verify_user('bob', 'builder789'))
    print("Verifying 'bob' with new password:", store_enc.verify_user('bob', 'newbuilder012'))
