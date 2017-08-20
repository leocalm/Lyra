import logging
import pytest
import subprocess

import yaml

from pathlib import Path

from tests.harness import valid_lyra2_output

logger = logging.getLogger(__name__)

fpath = Path(__file__).resolve()
parent = fpath.parent

with open(Path(fpath.parent, 'harness.yml')) as config:
    params = yaml.load(config)

    logging.config.dictConfig(params['logging'])

    data_path  = Path(parent, params['data_path']).resolve()
    build_path = Path(parent, params['build_path']).resolve()

@pytest.mark.parametrize(
    'fpath', list(build_path.glob("lyra2-*"))
)
def test_on_data(fpath):
    fname = fpath.name

    fdata = Path(data_path, fname, 'data.yml')

    if not fdata.exists():
        assert False, 'no data for: ' + fname

    with open(fdata) as src:
        data = yaml.load(src)

        for key, val in data.items():
            pwd = str(val['pwd'])
            salt = str(val['salt'])
            klen = str(val['klen'])
            tcost = str(val['tcost'])
            mcost = str(val['mcost'])

            process = subprocess.run(
                [fpath, pwd, salt, klen, tcost, mcost],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            msg = 'Failed: {pwd} {salt} {klen} {tcost} {mcost}'.format(**val)

            if process.returncode != 0:
                assert False, msg

            out = valid_lyra2_output(process.stdout)

            assert val['hash'] == out['hash'], msg
