# VulniFy
 a robust backend using Python to handle the core functionalities of the vulnerability assessment framework.
<h1>INTRODUCTION:</h1>
Our team has designed a framework for the vulnerability scans where the user is required to paste the URL of the website he/she is going to check for its vulnerability and flaws. Our framework ensures to deliver out the true and up to date information about the flaws in a very unique way.
Besides getting the vulnerability scan, user gets a description about the vulnerability so that he/she can check and work on it. It also shows how vulnerable your site is as low, medium, high risk using various colors.
TOOLS AND LIBRARIES USED
Flask: 
A micro web framework for Python.
Handles routing (@app.route) and HTTP requests (request object).
Renders HTML templates (render_template function).
SQLAlchemy: 
Object-Relational Mapping (ORM) library for Python.
Manages database models (Scan, Alert, NmapResult).
Handles database connections and queries (db.session).
Flask-Migrate: Extension for Flask to handle database migrations.
Simplifies the process of applying and managing database schema changes.
ZAPv2 (OWASP ZAP):
 Open-source web application security scanner.
Integrated for performing active and passive scans (zap.ascan and zap.pscan).
Retrieves security alerts (zap.core.alerts).
nmap: 
Network exploration tool and security/port scanner.
Used to perform network scans (nmap.PortScanner()).
Files and Directories:
App Initialization:
app = Flask(_name_, static_folder=r"C:\Users\(user's computer directory where template is stored)"): Defines the Flask application and specifies the static file directory.
Database Configuration:
app.config['SQLALCHEMY_DATABASE_URI']: Specifies the SQLite database location.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False: Disables SQLAlchemy modification tracking.
Database Models:
Defines three database models (Scan, Alert, NmapResult) using SQLAlchemy ORM.
Routes:
/: Serves the index.html file from the specified static directory.
/scan: Endpoint for initiating a scan, handling both ZAP and nmap scans, storing results in the database, and rendering a results template.
/scans: Displays a list of scan records from the database.
Templates:
index.html: Main HTML file served by the application.
results.html: Template for displaying scan results.
scans.html: Template for displaying a list of scan records.
Files and Directories Overview:
Static Files:
Located at C:\Users\(user's computer directory where template is stored).
Contains static assets like CSS, JavaScript, and index.html.
Database File:
SQLite database file (zap_scans.db).
