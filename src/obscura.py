import argparse
import secrets
import struct
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import List, NewType, Optional, Tuple

import argon2
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import aead

Salt = NewType("Salt", bytes)
Kek = NewType("Kek", bytes)

Dek = NewType("Dek", bytes)
WrappedDek = NewType("WrappedDek", bytes)

Nonce = NewType("Nonce", bytes)
CipherText = NewType("CipherText", bytes)
PlainText = NewType("PlainText", bytes)


@dataclass(frozen=True)
class Argon2Parameters:
    time_cost: int
    parallelism: int
    memory_cost: int


@dataclass(frozen=True)
class EncryptedFile:
    dek: WrappedDek
    salt: Salt
    nonce: Nonce
    argon2_parameters: Argon2Parameters
    cipher_text: CipherText

    @classmethod
    def read(cls, file: Path) -> "EncryptedFile":
        with file.open("rb") as reader:
            magic = reader.read(7)
            if magic != b"OBSCURA":
                raise ValueError("Unrecognized file format.")

            (
                dek,
                salt,
                nonce,
                argon2_time_cost,
                argon2_parallellism,
                argon2_memory_cost,
            ) = struct.unpack("40s32s12siii", reader.read(96))
            return cls(
                dek,
                salt,
                nonce,
                Argon2Parameters(
                    time_cost=argon2_time_cost,
                    parallelism=argon2_parallellism,
                    memory_cost=argon2_memory_cost,
                ),
                CipherText(reader.read()),
            )

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                b"OBSCURA",
                self.dek,
                self.salt,
                self.nonce,
                struct.pack(
                    "iii",
                    self.argon2_parameters.time_cost,
                    self.argon2_parameters.parallelism,
                    self.argon2_parameters.memory_cost,
                ),
                self.cipher_text,
            ]
        )


def kdf(
    passphrase: bytes, *, salt: Optional[Salt] = None, parameters: Argon2Parameters
) -> Tuple[Kek, Salt]:
    if salt is None:
        salt = Salt(secrets.token_bytes(32))
    kek = Kek(
        argon2.low_level.hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=parameters.time_cost,
            parallelism=parameters.parallelism,
            memory_cost=parameters.memory_cost,
            hash_len=32,
            type=argon2.Type.ID,
        )
    )
    return kek, salt


def generate_dek() -> Dek:
    return Dek(aead.AESGCM.generate_key(256))


def wrap_dek(kek: Kek, dek: Dek) -> WrappedDek:
    return WrappedDek(keywrap.aes_key_wrap(kek, dek))


def unwrap_dek(kek: Kek, dek: WrappedDek) -> Dek:
    return Dek(keywrap.aes_key_unwrap(kek, dek))


def encrypt(plain_text: PlainText, *, dek: Dek) -> Tuple[CipherText, Nonce]:
    nonce = Nonce(secrets.token_bytes(12))
    cipher_text = CipherText(aead.AESGCM(dek).encrypt(nonce, plain_text, None))
    return cipher_text, nonce


def decrypt(cipher_text: CipherText, *, dek: Dek, nonce: Nonce) -> PlainText:
    return PlainText(aead.AESGCM(dek).decrypt(nonce, cipher_text, None))


def encrypt_file(
    file: Path, *, passphrase: str, argon2_parameters: Argon2Parameters
) -> EncryptedFile:
    kek, salt = kdf(passphrase.encode(), parameters=argon2_parameters)
    dek = generate_dek()
    cipher_text, nonce = encrypt(PlainText(file.read_bytes()), dek=dek)
    return EncryptedFile(
        dek=wrap_dek(kek, dek),
        salt=salt,
        nonce=nonce,
        cipher_text=cipher_text,
        argon2_parameters=argon2_parameters,
    )


def decrypt_file(file: Path, *, passphrase: str) -> PlainText:
    enc_file = EncryptedFile.read(file)
    kek, _ = kdf(
        passphrase.encode(), salt=enc_file.salt, parameters=enc_file.argon2_parameters
    )
    return decrypt(
        cipher_text=enc_file.cipher_text,
        dek=unwrap_dek(kek, enc_file.dek),
        nonce=enc_file.nonce,
    )


def main(argv: List[str] = sys.argv[1:]) -> None:
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--decrypt", action="store_true")
    argparser.add_argument(
        "--argon2-time-cost", type=int, default=argon2.DEFAULT_TIME_COST
    )
    argparser.add_argument(
        "--argon2-parallellism", type=int, default=argon2.DEFAULT_PARALLELISM
    )
    argparser.add_argument(
        "--argon2-memory-cost", type=int, default=argon2.DEFAULT_MEMORY_COST
    )
    argparser.add_argument("file", type=Path)
    args = argparser.parse_args(argv)

    argon2_parameters = Argon2Parameters(
        time_cost=args.argon2_time_cost,
        parallelism=args.argon2_parallellism,
        memory_cost=args.argon2_memory_cost,
    )

    passphrase = getpass()

    if args.decrypt:
        sys.stdout.buffer.write(decrypt_file(args.file, passphrase=passphrase))
    else:
        sys.stdout.buffer.write(
            encrypt_file(
                args.file,
                passphrase=passphrase,
                argon2_parameters=argon2_parameters,
            ).to_bytes(),
        )
    sys.stdout.flush()


if __name__ == "__main__":
    main()  # pragma: no cover
