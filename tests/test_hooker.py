import os
import pytest
import requests
import signal
import subprocess
import tempfile
import textwrap
import time

from contextlib import contextmanager

@contextmanager
def start_service(path, config, *args):
    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.write(config)
        f.flush()

        proc = subprocess.Popen(path + ["--config", f.name] + list(args), start_new_session=True)
        time.sleep(1)

        yield proc

        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait()


def test_service_start(hooker_path):
    CONFIG = textwrap.dedent("""\
        service:
            listen: 0.0.0.0
            port: 9977
        """)

    with start_service(hooker_path, CONFIG):
        response = requests.get("http://localhost:9977")
        assert response is not None

def test_hook_not_found(hooker_path):
    CONFIG = textwrap.dedent("""\
        service:
            listen: 0.0.0.0
            port: 9977
        """)

    with start_service(hooker_path, CONFIG):
        response = requests.get("http://localhost:9977/illegal-hook")
        assert response.status_code == 404

def test_hook_found(hooker_path):
    CONFIG = textwrap.dedent("""\
        service:
            listen: 0.0.0.0
            port: 9977
        endpoints:
            hook:
                action: /usr/bin/true
        """)

    with start_service(hooker_path, CONFIG):
        response = requests.get("http://localhost:9977/hook")
        assert response.status_code == 200

def test_hook_action(hooker_path):
    with tempfile.NamedTemporaryFile(mode="r") as f:

        CONFIG = textwrap.dedent(f"""\
            service:
                listen: 0.0.0.0
                port: 9977
            endpoints:
                hook:
                    action: echo "foo" > {f.name}
            """)

        with start_service(hooker_path, CONFIG):
            response = requests.get("http://localhost:9977/hook")
            assert response.status_code == 200
            assert f.read().strip() == "foo"
