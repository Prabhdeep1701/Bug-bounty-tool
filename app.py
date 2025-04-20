from flask import Flask, render_template, request, jsonify
from main import BugBountyAI
import threading
import os
from flask import send_from_directory
from flask import send_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'reports'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global variable to store scan status
scan_status = {'running': False, 'progress': 0, 'message': ''}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    global scan_status
    if scan_status['running']:
        return jsonify({'error': 'Scan already running'}), 400
    
    target_url = request.form.get('target_url')
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    scan_status = {'running': True, 'progress': 0, 'message': 'Starting scan...'}
    
    # Run scan in background thread
    def run_scan():
        try:
            scanner = BugBountyAI()
            scanner.run(target_url)
            scan_status['message'] = 'Scan completed successfully'
        except Exception as e:
            scan_status['message'] = f'Scan failed: {str(e)}'
        finally:
            scan_status['running'] = False
            scan_status['progress'] = 100
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({'message': 'Scan started successfully'})

@app.route('/scan_status')
def get_scan_status():
    return jsonify(scan_status)

@app.route('/reports')
def list_reports():
    reports = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.json'):
            reports.append({
                'name': filename,
                'path': os.path.join(app.config['UPLOAD_FOLDER'], filename)
            })
    return jsonify(reports)

@app.route('/download_report')
def download_report():
    try:
        reports = sorted(
            [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.endswith('.json')],
            key=lambda x: os.path.getmtime(os.path.join(app.config['UPLOAD_FOLDER'], x)),
            reverse=True
        )
        
        if reports:
            latest_report = reports[0]
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                latest_report,
                as_attachment=True,
                mimetype='application/json'
            )
        return jsonify({'error': 'No reports available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/report/<filename>')
def get_report(filename):
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)