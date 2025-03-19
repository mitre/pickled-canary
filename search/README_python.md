# Quick setup notes:

All in this directory:

- `python -m venv venv`
- `venv\Scripts\activate`
- `pip install --editable .`
- `pip install pytest`
- `pytest`

If you have Poetry installed:

- `poetry shell`
- `poetry install`
- `pip install --editable .`
- `pytest`

To slightly speed up tests:

- `pytest -o "testpaths=tests" -s`

To build a wheel:

- `pip wheel -w dist --no-deps .`

> Copyright (C) 2025 The MITRE Corporation All Rights Reserved
