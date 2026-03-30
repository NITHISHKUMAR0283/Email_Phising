# URL Detection Engine Integration

## Overview
The Email Phishing detector now integrates the **military-grade URL Detection engine** from the `URL_Detection-master` project.

### What Changed
- ❌ **OLD**: BERT-based URL classification (`CrabInHoney/urlbert-tiny-v4-phishing-classifier`)
- ✅ **NEW**: Comprehensive 13-phase URL analysis engine with multiple detection techniques

## New Files Created

### `app/url_analyzer.py`
Wrapper class that:
- Loads the URL Detection engine from `URL_Detection-master/engine`
- Provides `analyze_url()` and `analyze_urls()` functions
- Maps risk scores and threat types to standardized format
- Falls back to heuristics if engine unavailable

## Detection Features (13 Phases)

The integrated engine analyzes:

1. **Structural Analysis**
   - URL format, length, suspicious keywords
   - Protocol validation, path analysis

2. **Domain Intelligence**
   - Domain age, registrar reputation
   - WHOIS data, DNS records
   - TLD risk assessment

3. **Brand Detection**
   - Brand lookalike detection
   - Homoglyph analysis (lookalike characters)
   - Subdomain spoofing

4. **SSL/Certificate Analysis**
   - Certificate validity
   - Self-signed certificates
   - Issuer verification

5. **Redirect Analysis**
   - Redirect chains and loops
   - Shortener detection

6. **Threat Intelligence**
   - VirusTotal integration
   - Known phishing databases
   - Malware indicators

7. **Contextual Analysis**
   - Form detection (login/payment)
   - Brand-form combinations
   - Content analysis

8. **Whitelist Checking**
   - Known legitimate domains
   - Skip false positives

9. **Score Calculation**
   - Weighted risk factors
   - Multipliers for dangerous combinations
   - False positive prevention

## Usage in Phishing Engine

### Before (OLD BERT Model)
```python
# analyze_url() used BERT tokenizer
inputs = url_tokenizer(urls, return_tensors="pt", truncation=True, max_length=64)
probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[:, 1].tolist()
```

### After (NEW Detection Engine)
```python
from .url_analyzer import analyze_urls

analysis_result = analyze_urls(urls)
max_score = analysis_result['max_risk_score']  # 0-1 scale
suspicious_urls = analysis_result['suspicious_urls']
details = analysis_result['details']  # Rich findings for each URL
```

## Output Format

Each analyzed URL returns:
```json
{
  "url": "http://example.com",
  "risk_score": 0.75,
  "risk_level": "HIGH",
  "threat_type": "Brand Lookalike + SSL Issues",
  "findings": [
    "Brand lookalike detected",
    "Self-signed certificate",
    "New domain (3 days old)"
  ],
  "is_suspicious": true,
  "details": {
    "domain": {...},
    "structural": {...},
    "brand": {...},
    "certificate": {...},
    "redirect": {...},
    "threat_intel": {...},
    "contextual": {...},
    "verdict": {...}
  }
}
```

## Risk Score Mapping

| Score Range | Level | Meaning |
|-------|-------|---------|
| 0.0 - 0.2 | SAFE | No threats detected |
| 0.2 - 0.4 | LOW | Minor issues, generally safe |
| 0.4 - 0.6 | MEDIUM | Moderate risk, user should verify |
| 0.6 - 0.8 | HIGH | Strong phishing indicators |
| 0.8 - 1.0 | CRITICAL | Extreme threat |

## Configuration

The URL analyzer uses thresholds from `app/config.py`:
- `URL_SUSPICIOUS_THRESHOLD` = 0.55 (default)

To adjust sensitivity:
```python
# In app/config.py:
URL_SUSPICIOUS_THRESHOLD = 0.60  # More lenient
# or
URL_SUSPICIOUS_THRESHOLD = 0.50  # More aggressive
```

## Fallback Behavior

If the URL Detection engine is unavailable:
- Falls back to basic heuristic checks
- Detects: suspicious TLDs, keywords, IP addresses
- Still provides a risk score

## API Integration

### Quick Test
```bash
# Test URL analysis
curl -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Click here: http://totally-legit.tk",
    "urls": ["http://totally-legit.tk"]
  }'
```

The response will now include detailed URL findings from the 13-phase engine.

## Performance

- **Single URL**: ~50-200ms (depends on DNS/SSL checks)
- **Multiple URLs**: Processed in parallel using ThreadPoolExecutor
- **Caching**: URLs are cached within a session to avoid re-analysis

## Troubleshooting

### Import Error: "engine could not be resolved"
- This is normal - the engine is imported dynamically at runtime
- Check that `URL_Detection-master/` exists at the correct path
- The analyzer will fall back to heuristics if import fails

### All URLs showing as SAFE
- Check if `URL_SUSPICIOUS_THRESHOLD` in `config.py` is too high
- Lower the threshold to 0.50 to be more aggressive

### Slow Analysis
- URLs are analyzed in parallel - this overhead is normal for first email
- Subsequent emails use caching
- You can increase timeout in config if needed

## Dependencies

The URL Detection engine requires:
- python-Levenshtein
- jellyfish
- (Optional: dnspython for DNS checks)

These are listed in `URL_Detection-master/requirements.txt`.

Install if needed:
```bash
pip install -r URL_Detection-master/requirements.txt
```

## Next Steps

1. ✅ **Test** - Send emails with URLs and verify detection
2. 🔧 **Tune** - Adjust `URL_SUSPICIOUS_THRESHOLD` in `config.py`
3. 📊 **Monitor** - Track detection accuracy
4. 🎯 **Optimize** - Fine-tune 13-phase detection rules if needed
