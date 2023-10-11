import secrets
from pathlib import Path
from unittest import mock

import obscura
import pytest


class TestKeys:
    def test_kek_length_equals_dek_length_of_32_bytes(
        self, kek: obscura.Kek, dek: obscura.Dek
    ) -> None:
        assert len(kek) == len(dek) == 32  # noqa: PLR2004

    def test_wrap_unwrap_identity(self, kek: obscura.Kek, dek: obscura.Dek) -> None:
        assert obscura.unwrap_dek(kek, obscura.wrap_dek(kek, dek)) == dek

    def test_wrapped_dek_is_different_than_unwrapped_dek(
        self, kek: obscura.Kek, dek: obscura.Dek
    ) -> None:
        assert obscura.wrap_dek(kek, dek) != obscura.WrappedDek(dek)


class TestEncryption:
    def test_encrypt_decrypt_identity(self, dek: obscura.Dek) -> None:
        plain_text = obscura.PlainText(b"foo")
        cipher_text, nonce = obscura.encrypt(plain_text, dek=dek)
        assert obscura.decrypt(cipher_text, dek=dek, nonce=nonce) == plain_text

    def test_decrypt_empty_cipher_text_raises_exception(self, dek: obscura.Dek) -> None:
        with pytest.raises(Exception):  # noqa: B017
            # TODO: Change this exception to somthing better
            obscura.decrypt(
                obscura.CipherText(b""),
                dek=dek,
                nonce=obscura.Nonce(secrets.token_bytes(12)),
            )


class TestEncryptedFile:
    def test_marshall_unmarshall_identity(
        self, encrypted_file: obscura.EncryptedFile
    ) -> None:
        file = mock.Mock(spec=Path)
        file.open = mock.mock_open(read_data=encrypted_file.to_bytes())
        assert obscura.EncryptedFile.read(file) == encrypted_file

    def test_unmarshall_invalid_file_format_raises_exception(self):
        file = mock.Mock(spec=Path)
        file.open = mock.mock_open(read_data=b"foobar")
        with pytest.raises(ValueError):
            # TODO: Change this exception to somtehing better
            obscura.EncryptedFile.read(file)

    def test_encrypt_decrypt_identity(
        self, encrypted_file: obscura.EncryptedFile
    ) -> None:
        with mock.patch("obscura.EncryptedFile.read") as read:
            read.return_value = encrypted_file
            file = mock.Mock(spec=Path)
            assert (
                obscura.decrypt_file(file, passphrase="hunter2")  # noqa: S106
                == b"secret snowflake"
            )


class TestCommandLine:
    def test_encrypt(self, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
        getpass_patch = mock.patch("obscura.getpass", return_value="hunter2")
        read_bytes_patch = mock.patch(
            "obscura.Path.read_bytes", return_value=b"secret snowflake"
        )
        with getpass_patch, read_bytes_patch:
            obscura.main(["some_file"])

        captured = capsysbinary.readouterr()
        assert captured.out[:7] == b"OBSCURA"

    def test_decrypt(
        self,
        encrypted_file: obscura.EncryptedFile,
        capsysbinary: pytest.CaptureFixture[bytes],
    ) -> None:
        getpass_patch = mock.patch("obscura.getpass", return_value="hunter2")
        read_bytes_patch = mock.patch(
            "obscura.Path.open",
            mock.mock_open(read_data=encrypted_file.to_bytes()),
        )
        with getpass_patch, read_bytes_patch:
            obscura.main(["-d", "some_file"])

        captured = capsysbinary.readouterr()
        assert captured.out == b"secret snowflake"
