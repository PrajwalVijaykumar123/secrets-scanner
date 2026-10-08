"""
Deliberately insecure sample config for testing the scanner.
None of these are real, active credentials - they are synthetic strings
shaped like each vendor's key format, used only to verify detection.
"""

# AWS credentials (synthetic - AWS's own documented EXAMPLE key, always a false positive)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# AWS credentials (synthetic - NOT the AWS example key, should be flagged)
PROD_AWS_ACCESS_KEY_ID = "AKIAZZZZZZZZZZZZZZZZ"

# GitHub token (synthetic, 36 chars after prefix)
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"

# Slack token (synthetic)
SLACK_BOT_TOKEN = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"

# Stripe test key (synthetic)
STRIPE_TEST_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc12345678"

# Hardcoded password
DATABASE_PASSWORD = "SuperSecretP@ssw0rd123"

# DB connection string with embedded password
DATABASE_URL = "postgresql://admin:SuperSecretP@ssw0rd123@prod-db.internal:5432/app"

# Generic high-entropy secret with no known vendor pattern
INTERNAL_SIGNING_SECRET = "tg8K2mQp9vLxR4wZaB7nC3eF6hJ1sU0y"

# Private key header (synthetic)
RSA_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD91JUEE4q5VkWmQQNmDzz4nShT0mKx1RHN5sr5vCnO
-----END RSA PRIVATE KEY-----
"""
