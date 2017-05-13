import pytest
import subprocess

from pathlib import Path

bindir = Path(__file__).parent.parent.joinpath('bin')

@pytest.mark.parametrize(
    'path', list(bindir.glob("lyra2-*"))
)
@pytest.mark.parametrize('pwd', ['password', 'qwerty'])
@pytest.mark.parametrize('salt', ['salt', 'pepper'])
@pytest.mark.parametrize('k', [1, 2])
@pytest.mark.parametrize('t', [1, 2])
@pytest.mark.parametrize('m', [3, 4, 5, 6, 7, 8, 9, 10])
def test_sanity_0(path, pwd, salt, k, t, m):

    result = subprocess.run([path, pwd, salt, str(k), str(t), str(m)])

    assert result.returncode == 0
