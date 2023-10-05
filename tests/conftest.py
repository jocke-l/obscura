from pathlib import Path
from unittest import mock

import obscura
import pytest


@pytest.fixture
def argon2_parameters() -> obscura.Argon2Parameters:
    return obscura.Argon2Parameters(
        time_cost=1,
        parallelism=1,
        memory_cost=100,
    )


@pytest.fixture
def kek(argon2_parameters: obscura.Argon2Parameters) -> obscura.Kek:
    kek, _ = obscura.kdf(b"hunter2", parameters=argon2_parameters)
    return kek


@pytest.fixture
def dek() -> obscura.Dek:
    return obscura.generate_dek()


@pytest.fixture
def encrypted_file(
    argon2_parameters: obscura.Argon2Parameters,
) -> obscura.EncryptedFile:
    file = mock.Mock(spec=Path)
    file.read_bytes.return_value = b"secret snowflake"
    return obscura.encrypt_file(
        file, passphrase="hunter2", argon2_parameters=argon2_parameters  # noqa: S106
    )
