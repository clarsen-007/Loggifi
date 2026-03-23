<pre>
File Integrity Monitor using SHA-256
This will scan through a folder(s) and create a SHA-256 checksum of all files in the folder(s).
You can then verify file integrity from the checksum database.

Create a checksum database for the /etc folder:
python3 loggifi.integrity.monitor.py --create --folder /etc --db /var/lib/loggifi/loggifi.integrity.monitor.etc.folder.json

Verify files in /etc from checksum database:
python3 loggifi.integrity.monitor.py --verify --folder /etc --db /var/lib/loggifi/loggifi.integrity.monitor.etc.folder.json

options:
  -h, --help            show this help message and exit
  --help-notes [TOPIC], -H [TOPIC]
                        Show annotated help notes. Use -H alone for all topics, or -H <topic> for one. Topics: usage, database, folders, exclude, verify
  --create, -c          Create checksum database
  --verify, -v          Verify files against database
  --folders FOLDERS [FOLDERS ...], -f FOLDERS [FOLDERS ...]
                        Folders to monitor (default: /etc, /usr/local/bin)
  --db DB               Database file path (default: file_integrity.json)
  --exclude EXCLUDE [EXCLUDE ...], -e EXCLUDE [EXCLUDE ...]
                        Patterns to exclude from scanning (e.g., .log .tmp)

Examples:
  Create database:
    loggifi.integrity.monitor.py --create
    loggifi.integrity.monitor.py --create --folders /etc /usr/bin

  Verify files:
    loggifi.integrity.monitor.py --verify
    loggifi.integrity.monitor.py --verify --folders /etc /usr/bin

  Custom database file:
    loggifi.integrity.monitor.py --create --db custom_db.json
    loggifi.integrity.monitor.py --verify --db custom_db.json

  Exclude patterns:
    loggifi.integrity.monitor.py --create --exclude .log .tmp .cache
 <pre>
