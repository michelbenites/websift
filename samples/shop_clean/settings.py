"""Configuration for the clean sample shop.

Secrets are read from the environment, never hardcoded.
"""

import os

SECRET_KEY = os.environ.get("SHOP_SECRET_KEY")
DB_PASSWORD = os.environ.get("SHOP_DB_PASSWORD")
API_TOKEN = os.environ.get("SHOP_API_TOKEN")

SHOP_NAME = "Clean Shop (sample)"
PRODUCT_CATALOG_PATH = "static/catalog.json"
CATALOG_FEED_URL = "https://shop.example.test/feed/catalog"
