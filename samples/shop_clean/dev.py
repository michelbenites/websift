"""Development entry point for the clean sample shop."""

from .app import app

app.run(host="127.0.0.1", debug=False)
