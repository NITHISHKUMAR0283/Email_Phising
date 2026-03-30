"""
URL Analysis Integration
========================
Wraps the military-grade URL Detection engine for use in the phishing detector.
Replaces the BERT-based URL model with comprehensive multi-phase analysis.
"""

import sys
import os
from pathlib import Path

# Add URL_Detection-master to path so we can import its engine
url_detection_path = Path(__file__).parent.parent / "URL_Detection-master"
if str(url_detection_path) not in sys.path:
    sys.path.insert(0, str(url_detection_path))

# Also add engine subdirectory
engine_path = url_detection_path / "engine"
if str(engine_path) not in sys.path:
    sys.path.insert(0, str(engine_path))

try:
    # Try importing the engine
    from engine import URLAnalysisEngine
    URL_ENGINE_AVAILABLE = True
    print("✅ URL Detection Engine loaded successfully")
except ImportError as e:
    URL_ENGINE_AVAILABLE = False
    print(f"⚠️  URL Detection engine not available (fallback mode): {e}")


class URLAnalyzer:
    """
    Unified URL analyzer using the advanced detection engine.
    Provides comprehensive URL threat analysis.
    """
    
    def __init__(self):
        """Initialize the URL analysis engine."""
        if URL_ENGINE_AVAILABLE:
            self.engine = URLAnalysisEngine()
            print("✅ URL Detection Engine loaded")
        else:
            self.engine = None
            print("❌ URL Detection Engine not available")
    
    def analyze_url(self, url: str) -> dict:
        """
        Analyze a single URL using the comprehensive engine.
        
        Returns:
        {
            'url': str,
            'risk_score': float (0-1),
            'risk_level': str ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'),
            'threat_type': str,
            'findings': list of findings,
            'details': dict with detailed analysis,
            'is_suspicious': bool
        }
        """
        if not self.engine:
            return self._fallback_analysis(url)
        
        try:
            # Run full analysis through the engine
            result = self.engine.analyze(url)
            
            # Extract key information
            risk_score = result.get('risk_score', 0.0)
            
            # Map risk level
            if risk_score >= 0.8:
                risk_level = "CRITICAL"
            elif risk_score >= 0.6:
                risk_level = "HIGH"
            elif risk_score >= 0.4:
                risk_level = "MEDIUM"
            elif risk_score >= 0.2:
                risk_level = "LOW"
            else:
                risk_level = "SAFE"
            
            # Extract findings
            findings = result.get('flags', [])
            
            return {
                'url': url,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'threat_type': result.get('threat_type', 'Unknown'),
                'findings': findings,
                'details': {
                    'domain': result.get('domain', {}),
                    'structural': result.get('structural', {}),
                    'brand': result.get('brand', {}),
                    'certificate': result.get('certificate', {}),
                    'redirect': result.get('redirect', {}),
                    'threat_intel': result.get('threat_intel', {}),
                    'contextual': result.get('contextual', {}),
                    'verdict': result.get('verdict', {}),
                },
                'is_suspicious': risk_level in ('CRITICAL', 'HIGH', 'MEDIUM'),
                'raw_result': result  # Full analysis for debugging
            }
        except Exception as e:
            print(f"❌ URL Analysis Error: {str(e)}")
            return self._fallback_analysis(url)
    
    def analyze_urls(self, urls: list) -> dict:
        """
        Analyze multiple URLs and return aggregated results.
        
        Returns:
        {
            'urls_analyzed': int,
            'max_risk_score': float,
            'max_risk_level': str,
            'suspicious_urls': list,
            'details': list of individual analyses
        }
        """
        if not urls:
            return {
                'urls_analyzed': 0,
                'max_risk_score': 0.0,
                'max_risk_level': 'SAFE',
                'suspicious_urls': [],
                'details': []
            }
        
        analyses = []
        max_score = 0.0
        suspicious = []
        
        for url in urls:
            analysis = self.analyze_url(url)
            analyses.append(analysis)
            
            score = analysis['risk_score']
            if score > max_score:
                max_score = score
            
            if analysis['is_suspicious']:
                suspicious.append({
                    'url': url,
                    'risk_score': score,
                    'risk_level': analysis['risk_level'],
                    'threat_type': analysis['threat_type']
                })
        
        # Determine max risk level
        if max_score >= 0.8:
            max_level = "CRITICAL"
        elif max_score >= 0.6:
            max_level = "HIGH"
        elif max_score >= 0.4:
            max_level = "MEDIUM"
        elif max_score >= 0.2:
            max_level = "LOW"
        else:
            max_level = "SAFE"
        
        return {
            'urls_analyzed': len(urls),
            'max_risk_score': round(max_score, 3),
            'max_risk_level': max_level,
            'suspicious_urls': suspicious,
            'details': analyses
        }
    
    def _fallback_analysis(self, url: str) -> dict:
        """Fallback analysis when engine is not available."""
        # Basic heuristic checks
        risk_score = 0.0
        findings = []
        
        # Check for common phishing TLDs
        if url.endswith(('.tk', '.ml', '.ga', '.cf')):
            risk_score += 0.1
            findings.append("Suspicious TLD detected")
        
        # Check for suspicious keywords
        suspicious_keywords = ['verify', 'confirm', 'update', 'login', 'account', 'security', 'urgent']
        if any(kw in url.lower() for kw in suspicious_keywords):
            risk_score += 0.15
            findings.append("Suspicious keywords in URL")
        
        # Check for IP address
        if any(c.isdigit() for c in url) and url.count('.') >= 3:
            try:
                parts = url.split('/')[-1].split('?')[0].split('.')
                if len(parts) >= 4 and all(p.isdigit() or p == '' for p in parts[:4]):
                    risk_score += 0.2
                    findings.append("IP address used instead of domain")
            except:
                pass
        
        risk_level = "LOW" if risk_score >= 0.05 else "SAFE"
        
        return {
            'url': url,
            'risk_score': min(risk_score, 1.0),
            'risk_level': risk_level,
            'threat_type': 'Heuristic Detection',
            'findings': findings,
            'details': {},
            'is_suspicious': risk_score >= 0.1,
            'raw_result': None
        }


# Global instance
_url_analyzer = None

def get_url_analyzer():
    """Get or create the global URL analyzer instance."""
    global _url_analyzer
    if _url_analyzer is None:
        _url_analyzer = URLAnalyzer()
    return _url_analyzer


def analyze_url(url: str) -> dict:
    """Convenience function to analyze a single URL."""
    analyzer = get_url_analyzer()
    return analyzer.analyze_url(url)


def analyze_urls(urls: list) -> dict:
    """Convenience function to analyze multiple URLs."""
    analyzer = get_url_analyzer()
    return analyzer.analyze_urls(urls)
