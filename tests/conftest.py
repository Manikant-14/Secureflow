import importlib.util
import pathlib
import sys
import threading

import pytest
from werkzeug.serving import make_server

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))


def load_app(name):
    """Import app/<name>/app.py under a unique module name (both files are called app.py)."""
    module_name = f"{name}_app"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "app" / name / "app.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module  # Flask needs this to find the templates folder
    spec.loader.exec_module(module)
    return module.app


@pytest.fixture(scope="session")
def vulnerable_app():
    return load_app("vulnerable")


@pytest.fixture(scope="session")
def fixed_app():
    return load_app("fixed")


def _serve(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture(scope="session")
def vulnerable_url(vulnerable_app):
    server, url = _serve(vulnerable_app)
    yield url
    server.shutdown()


@pytest.fixture(scope="session")
def fixed_url(fixed_app):
    server, url = _serve(fixed_app)
    yield url
    server.shutdown()
