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
