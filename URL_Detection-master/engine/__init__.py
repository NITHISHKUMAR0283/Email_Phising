"""
Military-Grade URL Analysis Engine
===================================
Multi-phase threat detection pipeline with 13 analysis phases.
"""

from datetime import datetime, timezone
from .parser import URLParser
from .domain_intel import DomainIntelligence
from .brand_detection import BrandDetection
from .structural import StructuralAnalyzer
from .redirect_analysis import RedirectAnalyzer
from .certificate import CertificateAnalyzer
from .threat_intel import ThreatIntelligence
from .whitelist import WhitelistChecker
from .contextual import ContextualAnalyzer
from .scoring import RiskScorer
from .classifier import ThreatClassifier
from .false_positive import FalsePositivePrevention
from .output import OutputGenerator


class URLAnalysisEngine:
    """
    Orchestrates all 13 analysis phases and produces a comprehensive
    threat assessment for a given URL.
    """

    def __init__(self):
        self.parser = URLParser()
        self.domain_intel = DomainIntelligence()
        self.brand_detection = BrandDetection()
        self.structural = StructuralAnalyzer()
        self.redirect = RedirectAnalyzer()
        self.certificate = CertificateAnalyzer()
        self.threat_intel = ThreatIntelligence()
        self.whitelist = WhitelistChecker()
        self.contextual = ContextualAnalyzer()
        self.scorer = RiskScorer()
        self.classifier = ThreatClassifier()
        self.fp_prevention = FalsePositivePrevention()
        self.output_gen = OutputGenerator()

    def analyze(self, url: str) -> dict:
        """Run full 13-phase analysis pipeline on a URL."""
        context = {
            'original_url': url,
            'risk_factors': [],
            'risk_score': 0.0,
            'flags': [],
            'detection_methods': [],
            'checks_performed': 0,
        }

        # Phase 1: Parse & Normalize
        parsed = self.parser.parse(url)
        context['parsed'] = parsed
        context['risk_factors'].extend(parsed.get('risk_factors', []))
        context['detection_methods'].append('URL Parsing & Normalization')
        context['checks_performed'] += parsed.get('checks_performed', 0)

        # Phase 2: Domain Intelligence
        domain_result = self.domain_intel.analyze(parsed)
        context['domain'] = domain_result
        context['risk_factors'].extend(domain_result.get('risk_factors', []))
        context['detection_methods'].append('Domain Intelligence Analysis')
        context['checks_performed'] += domain_result.get('checks_performed', 0)

        # Phase 3: Brand Impersonation Detection
        brand_result = self.brand_detection.analyze(parsed, domain_result)
        context['brand'] = brand_result
        context['risk_factors'].extend(brand_result.get('risk_factors', []))
        context['detection_methods'].append('Brand Impersonation Detection')
        context['checks_performed'] += brand_result.get('checks_performed', 0)

        # Phase 4: Structural & Behavioral Analysis
        structural_result = self.structural.analyze(parsed)
        context['structural'] = structural_result
        context['risk_factors'].extend(structural_result.get('risk_factors', []))
        context['detection_methods'].append('Structural & Behavioral Analysis')
        context['checks_performed'] += structural_result.get('checks_performed', 0)

        # Phase 5: Redirect & Shortener Analysis
        redirect_result = self.redirect.analyze(parsed)
        context['redirect'] = redirect_result
        context['risk_factors'].extend(redirect_result.get('risk_factors', []))
        context['detection_methods'].append('Redirect & Shortener Analysis')
        context['checks_performed'] += redirect_result.get('checks_performed', 0)

        # Phase 6: Certificate & Security Analysis
        cert_result = self.certificate.analyze(parsed)
        context['certificate'] = cert_result
        context['risk_factors'].extend(cert_result.get('risk_factors', []))
        context['detection_methods'].append('Certificate & Security Analysis')
        context['checks_performed'] += cert_result.get('checks_performed', 0)

        # Phase 7: Threat Intelligence
        threat_result = self.threat_intel.analyze(parsed, domain_result, brand_result)
        context['threat'] = threat_result
        context['risk_factors'].extend(threat_result.get('risk_factors', []))
        context['detection_methods'].append('Threat Intelligence Simulation')
        context['checks_performed'] += threat_result.get('checks_performed', 0)

        # Phase 8: Whitelist & Trust Verification
        whitelist_result = self.whitelist.check(parsed, context)
        context['whitelist'] = whitelist_result
        context['risk_factors'].extend(whitelist_result.get('risk_factors', []))
        context['detection_methods'].append('Whitelist & Trust Verification')
        context['checks_performed'] += whitelist_result.get('checks_performed', 0)

        # Phase 9: Contextual Intelligence
        contextual_result = self.contextual.analyze(parsed, context)
        context['contextual'] = contextual_result
        context['risk_factors'].extend(contextual_result.get('risk_factors', []))
        context['detection_methods'].append('Contextual Intelligence')
        context['checks_performed'] += contextual_result.get('checks_performed', 0)

        # Phase 10: Scoring
        score_result = self.scorer.calculate(context)
        context['score'] = score_result
        context['risk_score'] = score_result['final_score']
        context['detection_methods'].append('Advanced Scoring Algorithm')
        context['checks_performed'] += 1

        # Phase 11: Classification
        classification = self.classifier.classify(context)
        context['classification'] = classification
        context['detection_methods'].append('Classification & Confidence')
        context['checks_performed'] += 1

        # Phase 12: False Positive Prevention
        fp_result = self.fp_prevention.verify(context)
        context['fp_check'] = fp_result
        context['detection_methods'].append('False Positive Prevention')
        context['checks_performed'] += fp_result.get('checks_performed', 0)

        # Apply FP adjustments
        if fp_result.get('category_override'):
            context['classification']['category'] = fp_result['category_override']
        if fp_result.get('score_override') is not None:
            context['risk_score'] = fp_result['score_override']
        if fp_result.get('confidence_override'):
            context['classification']['confidence'] = fp_result['confidence_override']

        # Phase 13: Output Generation
        output = self.output_gen.generate(context)
        return output
