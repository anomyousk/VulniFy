from flask import Flask, request, jsonify, render_template, send_from_directory
from zapv2 import ZAPv2
from flask_sqlalchemy import SQLAlchemy
import os
import time
from flask_migrate import Migrate
import nmap

app = Flask(__name__, static_folder=r"C:\Users\nehal\AppData\Roaming\Microsoft\Windows\Templates")

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zap_scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize ZAP API client
zap = ZAPv2(apikey='6js95ca2qv5fr7d7h17l38u0a', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})

# Database models
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    alerts = db.relationship('Alert', backref='scan', lazy=True)
    nmap_results = db.relationship('NmapResult', backref='scan', uselist=False)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    risk = db.Column(db.String(50), nullable=False)
    alert = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(200), nullable=False)

class NmapResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    host = db.Column(db.String(200), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(50), nullable=False)
    service = db.Column(db.String(200))

    def __repr__(self):
        return f'<NmapResult host={self.host}, port={self.port}, protocol={self.protocol}, service={self.service}>'

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Open URL in ZAP
        zap.urlopen(url)
        time.sleep(2)

        # Start passive scan
        zap.pscan.enable_all_scanners()
        time.sleep(2)

        # Start active scan
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(5)

        # Get alerts from ZAP
        alerts = zap.core.alerts(baseurl=url)
        categorized_alerts = {
            'High': [],
            'Medium': [],
            'Low': [],
            'Informational': []
        }

        # Store ZAP alerts in database
        scan = Scan(url=url, status='Completed')
        db.session.add(scan)
        db.session.commit()

        for alert in alerts:
            risk = alert['risk']
            categorized_alerts[risk].append(alert)
            new_alert = Alert(scan_id=scan.id, risk=alert['risk'], alert=alert['alert'], description=alert['description'], url=alert['url'])
            db.session.add(new_alert)
        
        # Perform Nmap scan
        nm = nmap.PortScanner()
        nm.scan(url, arguments='-sV -O')

        # Store Nmap scan results in database
        if nm.all_hosts():
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        service = nm[host][proto][port]['product']
                        nmap_result = NmapResult(scan_id=scan.id, host=host, port=int(port), protocol=proto, service=service)
                        db.session.add(nmap_result)

        db.session.commit()

        return render_template('results.html', categorized_alerts=categorized_alerts)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scans')
def scans():
    scan_records = Scan.query.all()
    return render_template('scans.html', scan_records=scan_records)

if __name__ == '__main__':
    app.run(debug=True)
