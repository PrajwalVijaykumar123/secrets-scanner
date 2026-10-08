"""
Clean sample config - no real secrets, all values are placeholders or
read from the environment. The scanner should report zero findings here;
this file is the false-positive check.
"""

import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

DATABASE_PASSWORD = os.environ["DB_PASSWORD"]
DATABASE_URL = "postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/app"

API_KEY = "your_api_key_here"
SECRET_TOKEN = "<YOUR_SECRET_TOKEN>"
STRIPE_KEY = "sk_test_CHANGEME"

DEBUG = True
MAX_RETRIES = 3
APP_NAME = "my-app"
