"""Compatibility entry point for older deployment configurations.

The canonical Flask application lives in main.py and is used by Render
(gunicorn main:app). Keep this module as a thin alias so older commands do
not accidentally start a second, divergent implementation.
"""
from main import app


if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
