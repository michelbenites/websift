import pytest

from conftest import findings_for


def hash_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-HASH"]


def random_findings(source):
    return [f for f in findings_for(source) if f.rule == "PY-RANDOM"]


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib\nhashlib.md5(password.encode()).hexdigest()\n",
        "import hashlib\nhashlib.sha1(password.encode()).hexdigest()\n",
        "import hashlib\nhashlib.md5(pwd).hexdigest()\n",
        "import hashlib\nhashlib.sha1(user_secret).hexdigest()\n",
        "import hashlib\nhashlib.new('md5', password.encode()).hexdigest()\n",
        "import hashlib\nhashlib.new('sha1', password.encode()).hexdigest()\n",
        "import hashlib as hl\nhl.md5(password.encode()).hexdigest()\n",
        "from hashlib import md5\nmd5(password.encode()).hexdigest()\n",
        "import hashlib\nhashlib.md5(data=password.encode()).hexdigest()\n",
    ],
)
def test_weak_hash_on_password_like_flagged(source):
    findings = hash_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 328
    assert findings[0].severity.value == "medium"


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib\nhashlib.sha256(password.encode()).hexdigest()\n",
        "import hashlib\nhashlib.md5(file_bytes).hexdigest()\n",
        "import hashlib\nhashlib.sha1(checksum_data).hexdigest()\n",
        "import hashlib\nhashlib.new('sha256', password.encode()).hexdigest()\n",
        "import hashlib\nhashlib.new('md5', file_bytes).hexdigest()\n",
    ],
)
def test_weak_hash_safe_variants_not_flagged(source):
    assert hash_findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import random\ntoken = random.choice(letters)\n",
        "import random\nsession_id = random.randint(1, 1000)\n",
        "import random\ndef make_token():\n    return random.getrandbits(32)\n",
        "import random\ndef reset_code():\n    return random.randrange(1000)\n",
        "import random\ncsrf_value = random.sample(letters, 8)\n",
        "import random\notp_code = random.choices(digits, k=6)\n",
        "import random as r\ntoken = r.choice(letters)\n",
        "from random import choice\ntoken = choice(letters)\n",
    ],
)
def test_weak_random_for_security_names_flagged(source):
    findings = random_findings(source)
    assert len(findings) == 1
    assert findings[0].cwe == 330
    assert findings[0].severity.value == "low"


@pytest.mark.parametrize(
    "source",
    [
        "import random\nx = random.choice(letters)\n",
        "import random\ndice_roll = random.randint(1, 6)\n",
        "import secrets\ntoken = secrets.token_hex(16)\n",
        "import secrets\ntoken = secrets.choice(letters)\n",
        "import random\ndef unrelated():\n    return random.choice(letters)\n",
    ],
)
def test_weak_random_safe_variants_not_flagged(source):
    assert random_findings(source) == []


def test_weak_random_joined_generator_expression():
    source = (
        "import random\n"
        "import string\n"
        "def make_session_token():\n"
        "    token = ''.join(random.choice(string.ascii_letters) for _ in range(24))\n"
        "    return token\n"
    )
    findings = random_findings(source)
    assert len(findings) == 1
