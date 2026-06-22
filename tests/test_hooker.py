import os
import pytest
import requests
import signal
import subprocess
import tempfile
import textwrap
import time

from pathlib import Path
from contextlib import contextmanager

@contextmanager
def start_service_with_config(path, config_file, *args):
    proc = subprocess.Popen(path + ["--config", config_file] + list(args), start_new_session=True)
    time.sleep(1)

    try:
        yield proc
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait()

@contextmanager
def start_service(path, config, *args):
    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.write(config)
        f.flush()

        with start_service_with_config(path, f.name, *args) as proc:
            yield proc

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

def test_hook_cooldown(hooker_path):
    CONFIG = textwrap.dedent(f"""\
        service:
            listen: 0.0.0.0
            port: 9977
        endpoints:
            hook:
                cool-down: 2s
                action: /usr/bin/true
        """)

    with start_service(hooker_path, CONFIG):
        response = requests.get("http://localhost:9977/hook")
        assert response.status_code == 200
        response = requests.get("http://localhost:9977/hook")
        assert response.status_code == 429
        time.sleep(2)
        response = requests.get("http://localhost:9977/hook")
        assert response.status_code == 200

def test_hook_config_dir(hooker_path):
    with tempfile.TemporaryDirectory() as tmpdir:

        path = Path(tmpdir)
        conf_dir = path / "conf.d"
        conf_dir.mkdir()

        hook_yaml = conf_dir / "hook.yaml"
        with open(hook_yaml, "w") as f:
            f.write(textwrap.dedent(f"""\
            endpoints:
                hook:
                    action: /usr/bin/true
            """))

        CONFIG = textwrap.dedent(f"""\
            service:
                listen: 0.0.0.0
                port: 9977
            config_dir: ./conf.d
            """)

        with open(path / "config.yaml", "w+") as f:
            f.write(CONFIG)
            f.flush()

        print(f"tmp-dir: {path}")

        with start_service_with_config(hooker_path, path / "config.yaml"):
            response = requests.get("http://localhost:9977/hook")
            assert response.status_code == 200
