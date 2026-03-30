"""
Protected Brand Database
========================
Comprehensive list of brands to detect impersonation attacks.
"""

FINANCIAL_BRANDS = [
    'paypal', 'stripe', 'square', 'venmo', 'cashapp', 'chase',
    'bankofamerica', 'wellsfargo', 'citibank', 'hsbc', 'barclays',
    'capitalone', 'americanexpress', 'discover', 'mastercard', 'visa',
    'revolut', 'wise'
]

TECH_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'meta', 'facebook',
    'netflix', 'adobe', 'dropbox', 'zoom', 'slack', 'github',
    'gitlab', 'atlassian', 'salesforce', 'oracle', 'ibm', 'cisco',
    'dell', 'hp', 'intel', 'nvidia', 'amd'
]

ECOMMERCE_BRANDS = [
    'amazon', 'ebay', 'etsy', 'shopify', 'walmart', 'target',
    'alibaba', 'aliexpress', 'bestbuy', 'homedepot', 'wayfair'
]

COMMUNICATION_BRANDS = [
    'gmail', 'outlook', 'yahoo', 'protonmail', 'whatsapp', 'telegram',
    'signal', 'twitter', 'instagram', 'linkedin', 'tiktok', 'snapchat',
    'reddit', 'discord'
]

SHIPPING_BRANDS = [
    'fedex', 'ups', 'dhl', 'usps', 'royalmail', 'auspost'
]

GOVERNMENT_BRANDS = [
    'irs', 'uscis', 'socialsecurity', 'medicare', 'hmrc', 'cra', 'ato'
]

CLOUD_BRANDS = [
    'aws', 'azure', 'googlecloud', 'cloudflare', 'digitalocean',
    'heroku', 'vercel'
]

# Combined unique set
ALL_BRANDS = list(set(
    FINANCIAL_BRANDS + TECH_BRANDS + ECOMMERCE_BRANDS +
    COMMUNICATION_BRANDS + SHIPPING_BRANDS + GOVERNMENT_BRANDS +
    CLOUD_BRANDS
))

# Brand to category mapping
BRAND_CATEGORIES = {}
for b in FINANCIAL_BRANDS:
    BRAND_CATEGORIES[b] = 'Financial'
for b in TECH_BRANDS:
    BRAND_CATEGORIES[b] = 'Technology'
for b in ECOMMERCE_BRANDS:
    BRAND_CATEGORIES.setdefault(b, 'E-commerce')
for b in COMMUNICATION_BRANDS:
    BRAND_CATEGORIES.setdefault(b, 'Communication')
for b in SHIPPING_BRANDS:
    BRAND_CATEGORIES[b] = 'Shipping'
for b in GOVERNMENT_BRANDS:
    BRAND_CATEGORIES[b] = 'Government'
for b in CLOUD_BRANDS:
    BRAND_CATEGORIES.setdefault(b, 'Cloud')

# Suspicious keywords used in combosquatting
COMBOSQUAT_KEYWORDS = [
    'verify', 'login', 'signin', 'secure', 'account', 'update',
    'confirm', 'validate', 'authenticate', 'billing', 'payment',
    'support', 'help', 'service', 'alert', 'security', 'check',
    'recovery', 'reset', 'unlock', 'restore', 'suspended',
    'limited', 'action', 'required', 'urgent', 'warning',
    'notification', 'resolution', 'center'
]
