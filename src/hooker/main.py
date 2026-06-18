import logging
import typer
import uvicorn
import subprocess
from fastapi import FastAPI, Response
from types import SimpleNamespace
from pathlib import Path
import yaml

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("hooker")

def run_action(action):
    log.info(f"running action")
    subprocess.run(action, shell=True)
    return {}

def dict_to_ns(d):
    if isinstance(d, dict):
        return SimpleNamespace(**{ k : dict_to_ns(v) for k, v in d.items() })
    return d

def build_app(config):
    app = FastAPI()

    if hasattr(config, "endpoints"):
        for key, value in vars(config.endpoints).items():
            log.info(f"adding route {key} with action '{value.action}'")
            app.add_api_route(f"/{key}", lambda : run_action(value.action), methods=["GET"])

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
