"""
Flask Web Application for Vulnerability Scan Engine
====================================================
Provides a web-based dashboard for:
- Triggering vulnerability scans
- Viewing scan results
- Browsing vulnerability details
"""

import json
import os
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory

from engine import VulnerabilityScanner, run_scan
from config import (
    FLASK_CONFIG,
    SCAN_RESULTS_FILE,
    get_vck_content_dir,
    get_fingerprint_path,
    ACTIVE_VCK_SOURCE,
    OUTPUT_DIR
)


# =============================================================================
# FLASK APP INITIALIZATION
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_CONFIG['SECRET_KEY']
app.config['DEBUG'] = FLASK_CONFIG['DEBUG']


# =============================================================================
# ROUTES
# =============================================================================

@app.route('/')
def index():
    """Main dashboard page - displays scan results table"""
    # Check if results exist
    results_exist = SCAN_RESULTS_FILE.exists()
    
    results_data = None
    if results_exist:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                results_data = json.load(f)
        except Exception:
            results_data = None
    
    return render_template('results.html', 
                          results_exist=results_exist,
                          results_data=results_data)


@app.route('/scan', methods=['POST'])
def trigger_scan():
    """
    API endpoint to trigger a vulnerability scan
    
    Optional POST parameters:
    - fingerprint_path: Custom path to fingerprint JSON
    """
    try:
        # Get optional parameters from request
        data = request.get_json() or {}
        fingerprint_path = data.get('fingerprint_path', None)
        
        # Run the scan
        scanner = VulnerabilityScanner(fingerprint_path)
        report = scanner.scan()
        scanner.save_report(report)
        
        return jsonify({
            'status': 'success',
            'message': 'Scan completed successfully',
            'scan_id': report['scan_id'],
            'summary': report['summary']
        })
    
    except FileNotFoundError as e:
        return jsonify({
            'status': 'error',
            'message': f'File not found: {str(e)}'
        }), 404
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/results')
def get_results():
    """
    API endpoint to get scan results
    Returns the latest scan results JSON
    """
    try:
        if SCAN_RESULTS_FILE.exists():
            with open(SCAN_RESULTS_FILE, 'r') as f:
                results = json.load(f)
            return jsonify(results)
        else:
            return jsonify({
                'status': 'error',
                'message': 'No scan results available. Please run a scan first.'
            }), 404
            
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'message': str(e)
        }), 500


@app.route('/dashboard')
def dashboard():
    """Results dashboard page"""
    # Check if results exist
    results_exist = SCAN_RESULTS_FILE.exists()
    
    results_data = None
    if results_exist:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                results_data = json.load(f)
        except Exception:
            results_data = None
    
    return render_template('results.html', 
                          results_exist=results_exist,
                          results_data=results_data)


@app.route('/api/config')
def get_config():
    """
    API endpoint to get current configuration
    """
    return jsonify({
        'active_vck_source': ACTIVE_VCK_SOURCE,
        'vck_content_dir': str(get_vck_content_dir()),
        'fingerprint_path': str(get_fingerprint_path()),
        'fingerprint_exists': get_fingerprint_path().exists(),
        'results_exist': SCAN_RESULTS_FILE.exists()
    })


@app.route('/api/vck-files')
def list_vck_files():
    """
    API endpoint to list available VCK files
    """
    content_dir = get_vck_content_dir()
    
    if not content_dir.exists():
        return jsonify({'files': [], 'error': 'Content directory not found'})
    
    vck_files = []
    for file_path in content_dir.rglob("*.xml"):
        vck_files.append({
            'name': file_path.name,
            'path': str(file_path.relative_to(content_dir)),
            'product': file_path.parent.name
        })
    
    return jsonify({'files': vck_files, 'count': len(vck_files)})


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Vulnerability Scan Engine',
        'version': '1.0.0'
    })


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔍 VULNERABILITY SCAN ENGINE - WEB DASHBOARD")
    print("="*60)
    print(f"Active VCK Source: {ACTIVE_VCK_SOURCE}")
    print(f"VCK Content Dir:   {get_vck_content_dir()}")
    print(f"Fingerprint Path:  {get_fingerprint_path()}")
    print("="*60)
    print(f"Starting server at http://{FLASK_CONFIG['HOST']}:{FLASK_CONFIG['PORT']}")
    print("="*60 + "\n")
    
    app.run(
        host=FLASK_CONFIG['HOST'],
        port=FLASK_CONFIG['PORT'],
        debug=FLASK_CONFIG['DEBUG']
    )
