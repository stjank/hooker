import datetime
import hiyapyco
import ipaddress
import logging
import os
import re
import subprocess
import typer
import uvicorn
import yaml

from fastapi import FastAPI, Response, Request, status
from pathlib import Path
from types import SimpleNamespace
from datetime import timedelta

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("uvicorn")

time_delta_regex = re.compile("((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?")
def parse_timedelta(s):
    if s is None:
        return None

    groups = time_delta_regex.match(s)
    if not groups:
        return None

    items = { name: float(value) for name, value in groups.groupdict().items() if value }
    return timedelta(**items)

def parse_access(config):
    if config is None:
        return None

    policy = getattr(config, 'policy', 'deny')

    allowed = [ipaddress.ip_network(cidr, strict=False) for cidr in getattr(config, 'allow', [])]
    denied = [ipaddress.ip_network(cidr, strict=False) for cidr in getattr(config, 'deny', [])]

    def access(request : Request):
        client_ip = ipaddress.ip_address(request.client.host)
        for net in denied:
            if client_ip in net:
                return False

        for net in allowed:
            if client_ip in net:
                return True

        return policy == 'allow'

    return access

class action(object):
    def __init__(self, config):
        self.command = config.action
        self.cool_down = parse_timedelta(getattr(config, 'cool-down', None))
        self.access = parse_access(getattr(config, 'access', None))
        self.last_run = None

    def run(self, request: Request, response : Response):
        if self.access and not self.access(request):
            response.status_code = status.HTTP_403_FORBIDDEN
            return {}

        if self.cool_down and self.last_run and self.last_run + self.cool_down > datetime.datetime.now():
            response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
            return {}

        log.info(f"running action")
        self.last_run = datetime.datetime.now()
        subprocess.run(self.command, shell=True)
        return {}

def dict_to_ns(d):
    if isinstance(d, dict):
        return SimpleNamespace(**{ k : dict_to_ns(v) for k, v in d.items() })
    return d

def build_app(config):
    app = FastAPI()

    if hasattr(config, "endpoints"):
        for key, value in vars(config.endpoints).items():
            act = action(value)
            app.add_api_route(f"/{key}", act.run, methods=["GET"])

    return app

def run_server(config):
    uvicorn.run(build_app(config), host=config.service.listen, port=config.service.port)

def load_config(config_file):
    conf = hiyapyco.load(str(config_file))
    if not 'config_dir' in conf:
        return conf

    dir_path = conf['config_dir']
    if dir_path.startswith('.'):
        dir_path = config_file.parent / dir_path

    files = [str(f) for f in Path(dir_path).glob("*.yaml")]
    return hiyapyco.load(str(config_file), *files, method=hiyapyco.METHOD_MERGE)

def start(host : str = typer.Option(None, help="listen address (0.0.0.0)"),
         port : int = typer.Option(None, help="port (8080)"),
         config : Path = typer.Option(None, help="path for config file")):

    if config is not None:
        dct = load_config(config)
        config_file = dict_to_ns(dct)
    else:
        config_file = SimpleNamespace(**{
            "host": "0.0.0.0",
            "port": 8080
        })

    if host is not None:
        config_file.service.listen = host

    if port is not None:
        config_file.service.port = port

    run_server(config_file)

def main():
    typer.run(start)

if __name__ == "__main__":
    main()
