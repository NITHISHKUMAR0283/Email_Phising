"""
Whitelist for legitimate senders and domains.
Helps reduce false positives for known legitimate email services.
"""

# Legitimate educational platforms
EDUCATIONAL_DOMAINS = {
    "coursera.org": "Coursera - Online learning platform",
    "udemy.com": "Udemy - Online courses",
    "udemymail.com": "Udemy - Course notifications",
    "e.udemymail.com": "Udemy - Email service domain",
    "edx.org": "edX - University courses",
    "skillshare.com": "Skillshare - Creative classes",
    "linkedin.com": "LinkedIn - Professional network",
    "linkedin-mail.com": "LinkedIn - Email domain",
    "github.com": "GitHub - Development platform",
    "githubmail.com": "GitHub - Email domain",
    "stackoverflow.com": "Stack Overflow - Developer Q&A",
    "kaggle.com": "Kaggle - Data science competition",
    "datacamp.com": "DataCamp - Data science courses",
    "pluralsight.com": "Pluralsight - Tech learning",
    "freecodecamp.org": "FreeCodeCamp - Coding bootcamp",
    "codecademy.com": "Codecademy - Interactive coding",
    "treehouse.com": "Treehouse - Web development",
    "masterclass.com": "Masterclass - Expert-led classes",
}

# Legitimate business/notification platforms
BUSINESS_DOMAINS = {
    "gmail.com": "Gmail",
    "outlook.com": "Microsoft Outlook",
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "amazon.com": "Amazon",
    "apple.com": "Apple",
    "slack.com": "Slack",
    "notion.so": "Notion",
    "dropbox.com": "Dropbox",
    "onedrive.live.com": "OneDrive",
    "icloud.com": "Apple iCloud",
    "protonmail.com": "ProtonMail",
}

# Known transactional email services (legitimate)
TRANSACTIONAL_DOMAINS = {
    "sendgrid.net": "SendGrid",
    "mailchimp.com": "Mailchimp",
    "constant-contact.com": "Constant Contact",
    "awssns.com": "AWS SNS",
    "mandrillapp.com": "Mandrill",
    "mailgun.org": "Mailgun",
    "sendgrid.com": "SendGrid",
    "notification.amazon.com": "Amazon Notifications",
    "email.amazon.com": "Amazon Email",
    "mail.pinterest.com": "Pinterest",
    "notify.twitter.com": "Twitter Notifications",
    "facebookmail.com": "Facebook",
    "redditmail.com": "Reddit",
}

# Social media & community platforms
SOCIAL_DOMAINS = {
    "twitter.com": "Twitter",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "reddit.com": "Reddit",
    "quora.com": "Quora",
    "medium.com": "Medium",
    "dev.to": "Dev.to",
    "hashnode.com": "Hashnode",
}

# Development/DevOps platforms
DEVELOPER_DOMAINS = {
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "heroku.com": "Heroku",
    "circleci.com": "CircleCI",
    "travis-ci.org": "Travis CI",
    "jenkins.io": "Jenkins",
    "docker.com": "Docker",
}

# Combine all whitelists
ALL_WHITELISTED_DOMAINS = {
    **EDUCATIONAL_DOMAINS,
    **BUSINESS_DOMAINS,
    **TRANSACTIONAL_DOMAINS,
    **SOCIAL_DOMAINS,
    **DEVELOPER_DOMAINS,
}

# Legitimate urgency keywords (NOT phishing when from these platforms)
LEGITIMATE_URGENCY_KEYWORDS = [
    # Educational/Learning urgency
    "start learning", "start course", "enroll now", "claim your",
    "limited spots", "register today", "get started", "begin learning",
    "course starts", "join now", "apply now", "limited time offer", "sign up today",
    
    # Transaction/Verification urgency (legitimate)
    "verification code", "code expires", "expires in", "6-digit",
    "temporary code", "one-time code", "otp", "2fa", "two-factor",
    "confirm your identity", "login verification", "access code",
    "password reset", "reset your password",  # legitimate context
    "complete registration", "finish signup", "activate account",
    "confirm email", "verify email", "validate email",
    "order confirmation", "payment confirmation",
]

# Educational platform specific keywords (legitimate marketing, not phishing)
EDUCATIONAL_KEYWORDS = [
    "course", "lessons", "tutorial", "curriculum", "instructor",
    "learning path", "certification", "skills", "training",
    "progress", "certificate", "enroll", "class", "subject",
    "lecture", "assignment", "quiz", "grading", "scholarship",
    "bootcamp", "seminar", "workshop", "webinar", "online class",
]


def is_domain_whitelisted(domain: str) -> bool:
    """Check if domain is in whitelist."""
    if not domain:
        return False
    
    domain_lower = domain.lower().strip()
    
    # Exact match
    if domain_lower in ALL_WHITELISTED_DOMAINS:
        return True
    
    # Check if subdomain of whitelisted domain
    for whitelisted in ALL_WHITELISTED_DOMAINS:
        if domain_lower.endswith("." + whitelisted) or domain_lower.endswith(whitelisted):
            return True
    
    return False


def get_whitelist_info(domain: str) -> str:
    """Get description of whitelisted domain."""
    domain_lower = domain.lower().strip()
    
    if domain_lower in ALL_WHITELISTED_DOMAINS:
        return ALL_WHITELISTED_DOMAINS[domain_lower]
    
    # Check subdomains
    for whitelisted, info in ALL_WHITELISTED_DOMAINS.items():
        if domain_lower.endswith("." + whitelisted):
            return f"Subdomain of {info}"
    
    return "Unknown"


def is_legitimate_urgency(text: str) -> bool:
    """
    Check if urgency language is legitimate (educational/marketing)
    vs phishing (credential theft, account issues).
    """
    text_lower = text.lower()
    
    # Count legitimate urgency Keywords
    legitimate_count = sum(1 for kw in LEGITIMATE_URGENCY_KEYWORDS if kw in text_lower)
    
    # Phishing urgency keywords
    phishing_urgency = [
        "verify your account", "confirm your identity", "unusual activity",
        "account suspended", "account locked", "security alert",
        "urgent action required for account", "reset your password immediately",
        "unauthorized access", "verify immediately or account closes"
    ]
    phishing_count = sum(1 for kw in phishing_urgency if kw in text_lower)
    
    # If has legitimate educational urgency but NOT phishing urgency = probably OK
    if legitimate_count > 0 and phishing_count == 0:
        return True
    
    # If has phishing urgency = definitely phishing regardless of legitimate urgency
    if phishing_count > 0:
        return False
    
    return False


def is_educational_content(text: str) -> bool:
    """Check if email is about education/learning (not phishing)."""
    if not text:
        return False
    
    text_lower = text.lower()
    educational_count = sum(1 for kw in EDUCATIONAL_KEYWORDS if kw in text_lower)
    
    # If 2+ educational keywords = probably legitimate educational email
    return educational_count >= 2
