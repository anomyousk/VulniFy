# VulniFy
 a robust backend using Python to handle the core functionalities of the vulnerability assessment framework.
<h1><b>INTRODUCTION</b></h1>
Our team has designed a framework for the vulnerability scans where the user is required to paste the URL of the website he/she is going to check for its vulnerability and flaws. Our framework ensures to deliver out the true and up to date information about the flaws in a very unique way.
Besides getting the vulnerability scan, user gets a description about the vulnerability so that he/she can check and work on it. It also shows how vulnerable your site is as low, medium, high risk using various colors.
<h1><b>TOOLS AND LIBRARIES USED<b></h1>
<h2>Flask: </h2>
A micro web framework for Python.
Handles routing (@app.route) and HTTP requests (request object).
Renders HTML templates (render_template function).
<h2>SQLAlchemy: </h2>
Object-Relational Mapping (ORM) library for Python.
Manages database models (Scan, Alert, NmapResult).
Handles database connections and queries (db.session).
<h2>Flask-Migrate:</h2> Extension for Flask to handle database migrations.
Simplifies the process of applying and managing database schema changes.
<h2>ZAPv2 (OWASP ZAP):</h2>
 Open-source web application security scanner.
Integrated for performing active and passive scans (zap.ascan and zap.pscan).
Retrieves security alerts (zap.core.alerts).
<h2>nmap: </h2>
Network exploration tool and security/port scanner.
Used to perform network scans (nmap.PortScanner()).
<h1><b>Files and Directories:</b></h1>
<h3>App Initialization:</h3>
app = Flask(_name_, static_folder=r"C:\Users\(user's computer directory where template is stored)"): Defines the Flask application and specifies the static file directory.
<h3>Database Configuration:</h3>
app.config['SQLALCHEMY_DATABASE_URI']: Specifies the SQLite database location.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False: Disables SQLAlchemy modification tracking.
<h3>Database Models:</h3>
Defines three database models (Scan, Alert, NmapResult) using SQLAlchemy ORM.
<h3>Routes:</h3>
/: Serves the index.html file from the specified static directory.
/scan: Endpoint for initiating a scan, handling both ZAP and nmap scans, storing results in the database, and rendering a results template.
/scans: Displays a list of scan records from the database.
<h3>Templates:</h3>
index.html: Main HTML file served by the application.
results.html: Template for displaying scan results.
scans.html: Template for displaying a list of scan records.
<h1><b>Files and Directories Overview:</b></h1>
<h3>Static Files:</h3>
Located at C:\Users\(user's computer directory where template is stored).
Contains static assets like CSS, JavaScript, and index.html.
<h3>Database File:</h3>
SQLite database file (zap_scans.db).
<code>from flask import Flask, request, jsonify, render_template, send_from_directory
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
</code>
<img src="https://ibb.co/SQq1Z3j">
<img src="https://ibb.co/MCBvZyb">
<img src="https://ibb.co/7p7wGRP">

