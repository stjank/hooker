import datetime
import logging
import re
import subprocess
import typer
import uvicorn
import yaml

from fastapi import FastAPI, Response, status
from pathlib import Path
from types import SimpleNamespace
from datetime import timedelta

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("hooker")

time_delta_regex = re.compile("((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?")
def parse_timedelta(s):
    if s is None:
        return None

    groups = time_delta_regex.match(s)
    if not groups:
        return None

    items = { name: float(value) for name, value in groups.groupdict().items() if value }
    return timedelta(**items)

class action(object):
    def __init__(self, config):
        self.command = config.action
        self.cool_down = parse_timedelta(getattr(config, 'cool-down', None))
        self.last_run = None

    def run(self, response : Response):
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

def start(host : str = typer.Option(None, help="listen address (0.0.0.0)"),
         port : int = typer.Option(None, help="port (8080)"),
         config : Path = typer.Option(None, help="path for config file")):

    if config is not None:
        with open(config) as f:
            config_file = dict_to_ns(yaml.safe_load(f))
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
