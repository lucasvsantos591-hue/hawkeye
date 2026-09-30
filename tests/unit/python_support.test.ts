import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readPythonInventory } from '../../src/core/ecosystems/python_inventory';
import { buildPythonIndex } from '../../src/core/python_index';

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-py-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

const find = (pkgs: any[], name: string) => pkgs.find(p => p.name === name);

describe('readPythonInventory', () => {
  it('reads uv.lock with the dependency graph and dev groups', () => {
    const dir = project({
      'pyproject.toml': '[project]\nname = "app"\ndependencies = ["flask>=2"]\n',
      'uv.lock': `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "flask" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "flask"
version = "2.0.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "werkzeug" }, { name = "jinja2" }]

[[package]]
name = "werkzeug"
version = "2.0.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "Jinja2"
version = "3.0.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
`,
    });
    const inv = readPythonInventory(dir);

    expect(inv.source).toBe('uv.lock');
    expect(find(inv.packages, 'flask')).toMatchObject({ version: '2.0.1', direct: true, dev: false });
    expect(find(inv.packages, 'jinja2')).toMatchObject({ direct: false, dev: false, via: ['flask'] });
    expect(find(inv.packages, 'pytest')).toMatchObject({ direct: true, dev: true });
    expect(find(inv.packages, 'app')).toBeUndefined();
  });

  it('reads poetry.lock with direct deps from pyproject groups', () => {
    const dir = project({
      'pyproject.toml': `[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.20"
[tool.poetry.group.dev.dependencies]
black = "^22.0"
`,
      'poetry.lock': `[[package]]
name = "requests"
version = "2.19.1"
[package.dependencies]
urllib3 = ">=1.21.1,<1.24"

[[package]]
name = "urllib3"
version = "1.23"

[[package]]
name = "black"
version = "22.1.0"
`,
    });
    const inv = readPythonInventory(dir);

    expect(inv.source).toBe('poetry.lock');
    expect(find(inv.packages, 'requests')).toMatchObject({ direct: true, dev: false });
    expect(find(inv.packages, 'urllib3')).toMatchObject({ direct: false, via: ['requests'] });
    expect(find(inv.packages, 'black')).toMatchObject({ dev: true });
  });

  it('uses pip-compile "# via" comments to tell direct from transitive', () => {
    const dir = project({
      'requirements.txt': `flask==2.0.1 \\
    --hash=sha256:abc
    # via -r requirements.in
jinja2==3.0.1
    # via flask
Werkzeug==2.0.1
    # via
    #   flask
`,
      'requirements-dev.txt': 'pytest==7.0.0\n',
    });
    const inv = readPythonInventory(dir);

    expect(find(inv.packages, 'flask')).toMatchObject({ version: '2.0.1', direct: true });
    expect(find(inv.packages, 'werkzeug')).toMatchObject({ direct: false, via: ['flask'] });
    expect(find(inv.packages, 'pytest')).toMatchObject({ dev: true });
  });

  it('marks pip freeze output as unknown directness and follows -r includes', () => {
    const dir = project({
      'requirements.txt': '-r requirements/base.txt\nPyYAML==5.3  # config\nunpinned-lib>=1.0\n',
      'requirements/base.txt': 'Django==3.2.0\n',
    });
    const inv = readPythonInventory(dir);

    expect(find(inv.packages, 'pyyaml')).toMatchObject({ version: '5.3', directKnown: false });
    expect(find(inv.packages, 'django')).toMatchObject({ version: '3.2.0' });
    expect(inv.warnings.join(' ')).toMatch(/unpinned/);
  });

  it('reads Pipfile.lock with Pipfile for directness', () => {
    const dir = project({
      Pipfile: '[packages]\nrequests = "*"\n[dev-packages]\npytest = "*"\n',
      'Pipfile.lock': JSON.stringify({
        default: { requests: { version: '==2.19.1' }, urllib3: { version: '==1.23' } },
        develop: { pytest: { version: '==7.0.0' } },
      }),
    });
    const inv = readPythonInventory(dir);

    expect(find(inv.packages, 'requests')).toMatchObject({ direct: true, dev: false });
    expect(find(inv.packages, 'urllib3')).toMatchObject({ direct: false, directKnown: true });
    expect(find(inv.packages, 'pytest')).toMatchObject({ dev: true });
  });
});

describe('buildPythonIndex', () => {
  const dir = project({
    'app/main.py': `from typing import TYPE_CHECKING
import yaml as y
import requests
from flask import Flask
import unused_pkg
if TYPE_CHECKING:
    from PIL import Image
app = Flask(__name__)
def handler(data):
    return requests.get(y.safe_load(data)["url"])
`,
    'app/settings.py': `INSTALLED_APPS = ["corsheaders", "rest_framework"]`,
    'tests/test_main.py': 'import pytest\nimport moto\nmoto.mock_s3()\n',
    Procfile: 'web: gunicorn app.main:app\n',
    '.venv/lib/python3.11/site-packages/requests/__init__.py': 'import should_not_be_indexed\n',
  });
  const index = buildPythonIndex(dir);

  it('tracks usage and members through aliases', () => {
    expect(index.usage('PyYAML')).toMatchObject({ used: true, members: ['safe_load'] });
    expect(index.usage('requests')).toMatchObject({ used: true, members: ['get'] });
    expect(index.usage('Flask')).toMatchObject({ used: true, members: ['Flask'] });
    expect(index.usage('requests')!.sites[0]).toMatch(/^app\/main\.py:\d+$/);
  });

  it('detects unused, TYPE_CHECKING-only and test-only imports', () => {
    expect(index.usage('unused-pkg')).toMatchObject({ used: false, typeOnly: false });
    expect(index.usage('pillow')).toMatchObject({ used: false, typeOnly: true });
    expect(index.usage('moto')).toMatchObject({ used: false, files: [], testFiles: ['tests/test_main.py'] });
  });

  it('counts string references in settings (Django apps) as usage', () => {
    expect(index.usage('django-cors-headers')?.used).toBe(true);
    expect(index.usage('djangorestframework')?.used).toBe(true);
  });

  it('recognizes packages started from Procfile / Docker commands', () => {
    expect(index.runtimeLoaded('gunicorn')).toMatch(/Procfile/);
    expect(index.runtimeLoaded('psycopg2-binary')).toMatch(/driver/);
    expect(index.runtimeLoaded('left-pad')).toBeNull();
  });

  it('skips virtualenvs', () => {
    expect(index.usage('should-not-be-indexed')).toBeUndefined();
    expect(index.filesScanned).toBe(3);
  });
});
