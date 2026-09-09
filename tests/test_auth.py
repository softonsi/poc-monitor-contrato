import bcrypt

from src.web_api.auth import _password_matches


def test_password_matches_bcrypt_hash():
    stored = bcrypt.hashpw(b"pedras", bcrypt.gensalt()).decode()

    assert _password_matches("pedras", stored)
    assert not _password_matches("errada", stored)


def test_password_matches_plain_text_legacy():
    assert _password_matches("softon123", "softon123")
    assert not _password_matches("errada", "softon123")
