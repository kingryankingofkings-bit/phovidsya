# Third-Party Notices

Aegis Shield itself is proprietary — see [LICENSE](LICENSE). This file is the
"separately identified third-party components" inventory that LICENSE §1 and §5
refer to. Nothing here transfers ownership of those components; each remains
governed by its own license.

## Runtime dependencies (Python)

Installed from PyPI at install time; no third-party source is vendored into this
repository.

| Component | Version reviewed | License | Project |
|---|---|---|---|
| `cryptography` | 50.0.0 | Apache-2.0 OR BSD-3-Clause | https://pypi.org/project/cryptography/ |
| `fastapi` | 0.141.1 | MIT | https://pypi.org/project/fastapi/ |
| `uvicorn` | 0.52.4 | BSD-3-Clause | https://pypi.org/project/uvicorn/ |
| `click` | 8.4.2 | BSD-3-Clause | https://pypi.org/project/click/ |
| `pydantic` | 2.13.4 | MIT | https://pypi.org/project/pydantic/ |
| `pyyaml` | 6.0.3 | MIT | https://pyyaml.org/ |

`uvicorn[standard]` additionally pulls in `httptools`, `uvloop`, `watchfiles`,
`websockets`, and `python-dotenv`, each under its own permissive license. Run
`pip-audit` and `pip install pip-licenses && pip-licenses` for the fully
resolved set for a given install.

## Development-only dependencies

`pytest`, `pytest-asyncio`, `httpx`, `anyio`, `coverage` — MIT or BSD-3-Clause.
Not distributed with the runtime.

## Rust workspace

The crates under `crates/` and `kernel/` are original work by the copyright
holder and have **no third-party dependencies**: every manifest declares an
empty `[dependencies]` section apart from path dependencies on sibling crates in
this workspace. `Cargo.lock` records the complete graph.

## Regenerating

This inventory is checked by CI. Regenerate after any dependency change:

```bash
pip install pip-licenses && pip-licenses --format=markdown
cargo tree --workspace
```
