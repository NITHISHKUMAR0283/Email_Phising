"""
Military-Grade URL Analysis Engine — Flask Application
=======================================================
Production-grade REST API for URL threat analysis.
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

from engine import URLAnalysisEngine

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)

# Initialize engine once
engine = URLAnalysisEngine()


@app.route('/')
def index():
    """Serve the main dashboard."""
    return send_from_directory('static', 'index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Analyze a URL for threats."""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing required field: url',
                'status': 'error'
            }), 400

        url = data['url'].strip()
        if not url:
            return jsonify({
                'error': 'URL cannot be empty',
                'status': 'error'
            }), 400

        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://', 'javascript:', 'data:', 'file://')):
            url = 'https://' + url

        # Run analysis
        result = engine.analyze(url)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            'error': f'Analysis failed: {str(e)}',
            'status': 'error'
        }), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'operational',
        'engine': 'URL Analysis Engine v2.0',
        'phases': 13
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
