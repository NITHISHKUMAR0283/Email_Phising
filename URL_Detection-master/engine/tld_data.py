"""
TLD Risk Classification Data
"""

CRITICAL_RISK_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}

HIGH_RISK_TLDS = {
    '.xyz', '.top', '.work', '.click', '.link', '.online',
    '.site', '.website', '.space', '.pw', '.cc'
}

MODERATE_RISK_TLDS = {'.ru', '.cn', '.in', '.br'}

NEUTRAL_TLDS = {'.com', '.net', '.org', '.edu', '.gov', '.info', '.biz', '.co'}

TRUSTED_TLDS = {'.edu', '.gov', '.mil'}

# TLD risk weights
TLD_RISK_WEIGHTS = {}
for tld in CRITICAL_RISK_TLDS:
    TLD_RISK_WEIGHTS[tld] = 0.35
for tld in HIGH_RISK_TLDS:
    TLD_RISK_WEIGHTS[tld] = 0.25
for tld in MODERATE_RISK_TLDS:
    TLD_RISK_WEIGHTS[tld] = 0.15
for tld in NEUTRAL_TLDS:
    TLD_RISK_WEIGHTS[tld] = 0.00
for tld in TRUSTED_TLDS:
    TLD_RISK_WEIGHTS[tld] = -0.05


def get_tld_risk(tld: str) -> tuple:
    """Returns (risk_level_name, risk_weight) for a TLD."""
    tld = tld.lower()
    if not tld.startswith('.'):
        tld = '.' + tld

    if tld in CRITICAL_RISK_TLDS:
        return ('CRITICAL', 0.35)
    elif tld in HIGH_RISK_TLDS:
        return ('HIGH', 0.25)
    elif tld in MODERATE_RISK_TLDS:
        return ('MODERATE', 0.15)
    elif tld in TRUSTED_TLDS:
        return ('TRUSTED', -0.05)
    elif tld in NEUTRAL_TLDS:
        return ('NEUTRAL', 0.00)
    else:
        return ('NEUTRAL', 0.00)
