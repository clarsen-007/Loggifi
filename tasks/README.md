<h1>tasks</h1>
<h2>This is part of my loggifi suite of tools...</h2>

<pre>
tasks: Is a Web UI created via Python and used as a tasks, to do list.
It includes the ability to run over HTTPS if you add certificates,
or it can be configured to run behind a reverse proxy or similar setup.

Change values in python script as required:
  
DATA_PATH_BASE_DIR = "/var/lib/loggifi"                 <<<<<<<<<< Path to create the SQLite database

CERT_PATH_BASE_DIR = "/opt/loggifi/certs/tasks/"                 <<<<<<<<<< Path to Certificates

DB_PATH   = os.path.join(DATA_PATH_BASE_DIR, "loggifi_tasks.db")                 <<<<<<<<<< SQLite atabase name
CERT_FILE = os.path.join(CERT_PATH_BASE_DIR, "cert.pem")                 <<<<<<<<<< Certificate file name
KEY_FILE  = os.path.join(CERT_PATH_BASE_DIR, "key.pem")                 <<<<<<<<<< Key file name
                                                                          
</pre>

<img src="loggifi.tasks.screenshot.png" alt="Project Screenshot" width="900">
