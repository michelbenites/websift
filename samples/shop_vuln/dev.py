"""Development entry point for the vulnerable sample shop."""

from .app import app

app.run(host="0.0.0.0", debug=True)
