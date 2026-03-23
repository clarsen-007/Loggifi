#!/usr/bin/env python3
"""
File Integrity Monitor using SHA-256
Monitors specified directories for file tampering
Created by clarsen-007
"""

import os
import sys
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

# Configuration
DATABASE_FILE = "file_integrity.json"
FOLDERS_TO_MONITOR = [
    "/etc",
    "/usr/local/bin",
    # Add more folders here
]

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ---------------------------------------------------------------------------
# HELP_NOTES: Add your own notes here, keyed by topic name.
# To annotate a section in the script, place a ##HELP: <topic> comment above
# it — show_help_notes() will find those markers and print the matching note.
#
# Example marker usage (place anywhere in the script):
#   ##HELP: database
#   ##HELP: folders
# ---------------------------------------------------------------------------
HELP_NOTES = {
    "usage": (
        "Run with --create first to build the baseline checksum database,\n"
        "then run with --verify on a schedule to detect changes."
    ),
    "database": (
        "The database is a plain JSON file storing SHA-256 checksums, file\n"
        "sizes, and modification times. Keep it in a safe, read-only location\n"
        "so an attacker cannot update it to cover their tracks."
    ),
    "folders": (
        "Edit FOLDERS_TO_MONITOR at the top of this file to set the default\n"
        "directories, or pass them at runtime with --folders. Avoid scanning\n"
        "volatile paths like /tmp or /proc."
    ),
    "exclude": (
        "Use --exclude to skip noisy file extensions such as .log or .tmp.\n"
        "Patterns are matched as substrings of the filename."
    ),
    "verify": (
        "Verification exit codes: 0 = all files match, 1 = discrepancies found.\n"
        "Suitable for use in cron jobs or CI pipelines."
    ),
}


def show_help_notes(topic: str = None):
    """
    Print entries from HELP_NOTES.
    If topic is given, print only that entry (and list any ##HELP: markers
    found in the script source that reference it).
    If topic is None, print all entries.
    """
    script_path = os.path.abspath(__file__)
    # Collect ##HELP: markers from source
    markers: Dict[str, List[int]] = {}
    try:
        with open(script_path, "r") as fh:
            for lineno, line in enumerate(fh, 1):
                stripped = line.strip()
                if stripped.startswith("##HELP:"):
                    key = stripped[len("##HELP:"):].strip()
                    markers.setdefault(key, []).append(lineno)
    except OSError:
        pass

    topics = [topic] if topic else list(HELP_NOTES.keys())

    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Help Notes{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    found_any = False
    for t in topics:
        note = HELP_NOTES.get(t)
        if note is None:
            print(f"{Colors.RED}No help note found for topic: '{t}'{Colors.RESET}")
            print(f"Available topics: {', '.join(HELP_NOTES.keys())}")
            continue
        found_any = True
        print(f"\n{Colors.BOLD}{Colors.BLUE}[{t}]{Colors.RESET}")
        print(f"  {note.replace(chr(10), chr(10) + '  ')}")
        if t in markers:
            lines = ', '.join(str(ln) for ln in markers[t])
            print(f"  {Colors.YELLOW}↳ Referenced at line(s): {lines}{Colors.RESET}")

    if found_any and not topic:
        print(f"\n{Colors.BOLD}Tip:{Colors.RESET} Use  -H <topic>  to view a single note.")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")


def calculate_sha256(filepath: str) -> str:
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, OSError) as e:
        print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.RESET}")
        return None


def scan_directories(folders: List[str], exclude_patterns: List[str] = None) -> Dict[str, Dict]:
    """
    Scan directories and create checksums for all files

    Args:
        folders: List of folder paths to scan
        exclude_patterns: List of patterns to exclude (e.g., ['.log', '.tmp'])

    Returns:
        Dictionary with file paths as keys and metadata as values
    """
    if exclude_patterns is None:
        exclude_patterns = []

    file_database = {}
    total_files = 0

    for folder in folders:
        if not os.path.exists(folder):
            print(f"{Colors.YELLOW}Warning: Folder '{folder}' does not exist, skipping...{Colors.RESET}")
            continue

        print(f"{Colors.BLUE}Scanning folder: {folder}{Colors.RESET}")

        for root, dirs, files in os.walk(folder):
            for filename in files:
                # Skip files matching exclude patterns
                if any(pattern in filename for pattern in exclude_patterns):
                    continue

                filepath = os.path.join(root, filename)

                # Skip symbolic links
                if os.path.islink(filepath):
                    continue

                try:
                    # Get file metadata
                    stat_info = os.stat(filepath)
                    checksum = calculate_sha256(filepath)

                    if checksum:
                        file_database[filepath] = {
                            "checksum": checksum,
                            "size": stat_info.st_size,
                            "modified": stat_info.st_mtime,
                            "scanned": datetime.now().isoformat()
                        }
                        total_files += 1

                        if total_files % 100 == 0:
                            print(f"  Processed {total_files} files...", end='\r')

                except (IOError, OSError, PermissionError) as e:
                    print(f"{Colors.YELLOW}Warning: Cannot access {filepath}: {e}{Colors.RESET}")
                    continue

        print(f"  {Colors.GREEN}Completed scanning: {folder}{Colors.RESET}")

    print(f"\n{Colors.BOLD}{Colors.GREEN}Total files scanned: {total_files}{Colors.RESET}")
    return file_database


def create_database(folders: List[str], db_file: str, exclude_patterns: List[str] = None):
    """Create checksum database"""
    print(f"{Colors.BOLD}=== Creating File Integrity Database ==={Colors.RESET}\n")

    file_database = scan_directories(folders, exclude_patterns)

    # Save to JSON file
    database = {
        "created": datetime.now().isoformat(),
        "folders": folders,
        "files": file_database
    }

    try:
        with open(db_file, 'w') as f:
            json.dump(database, f, indent=2)
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Database created successfully: {db_file}{Colors.RESET}")
        print(f"{Colors.GREEN}  Total files: {len(file_database)}{Colors.RESET}")
    except IOError as e:
        print(f"{Colors.RED}Error writing database: {e}{Colors.RESET}")
        sys.exit(1)


def verify_files(folders: List[str], db_file: str, exclude_patterns: List[str] = None) -> bool:
    """
    Verify files against the database

    Returns:
        True if all files match, False if any discrepancies found
    """
    print(f"{Colors.BOLD}=== Verifying File Integrity ==={Colors.RESET}\n")

    # Load database
    if not os.path.exists(db_file):
        print(f"{Colors.RED}Error: Database file '{db_file}' not found!{Colors.RESET}")
        print(f"{Colors.YELLOW}Please run with --create flag first to create the database.{Colors.RESET}")
        sys.exit(1)

    try:
        with open(db_file, 'r') as f:
            database = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"{Colors.RED}Error reading database: {e}{Colors.RESET}")
        sys.exit(1)

    stored_files = database.get("files", {})
    print(f"Database created: {database.get('created', 'Unknown')}")
    print(f"Files in database: {len(stored_files)}\n")

    # Scan current files
    current_files = scan_directories(folders, exclude_patterns)

    # Compare
    print(f"\n{Colors.BOLD}=== Verification Results ==={Colors.RESET}\n")

    modified_files = []
    new_files = []
    deleted_files = []
    unchanged_files = 0

    # Check for modified and unchanged files
    for filepath, metadata in current_files.items():
        if filepath in stored_files:
            if metadata["checksum"] != stored_files[filepath]["checksum"]:
                modified_files.append(filepath)
            else:
                unchanged_files += 1
        else:
            new_files.append(filepath)

    # Check for deleted files
    for filepath in stored_files.keys():
        if filepath not in current_files:
            deleted_files.append(filepath)

    # Display results
    all_ok = True

    if modified_files:
        all_ok = False
        print(f"{Colors.RED}{Colors.BOLD} MODIFIED FILES ({len(modified_files)}):{Colors.RESET}")
        for filepath in modified_files:
            print(f"{Colors.RED}  - {filepath}{Colors.RESET}")
        print()

    if new_files:
        all_ok = False
        print(f"{Colors.YELLOW}{Colors.BOLD} NEW FILES ({len(new_files)}):{Colors.RESET}")
        for filepath in new_files:
            print(f"{Colors.YELLOW}  + {filepath}{Colors.RESET}")
        print()

    if deleted_files:
        all_ok = False
        print(f"{Colors.YELLOW}{Colors.BOLD} DELETED FILES ({len(deleted_files)}):{Colors.RESET}")
        for filepath in deleted_files:
            print(f"{Colors.YELLOW}  - {filepath}{Colors.RESET}")
        print()

    # Summary
    print(f"{Colors.BOLD}=== Summary ==={Colors.RESET}")
    print(f"{Colors.GREEN}Unchanged files: {unchanged_files}{Colors.RESET}")
    print(f"{Colors.RED}Modified files:  {len(modified_files)}{Colors.RESET}")
    print(f"{Colors.YELLOW}New files:       {len(new_files)}{Colors.RESET}")
    print(f"{Colors.YELLOW}Deleted files:   {len(deleted_files)}{Colors.RESET}")

    if all_ok:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ ALL FILES VERIFIED SUCCESSFULLY{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}✗ VERIFICATION FAILED - DISCREPANCIES FOUND{Colors.RESET}")

    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor using SHA-256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Create database:
    %(prog)s --create
    %(prog)s --create --folders /etc /usr/bin

  Verify files:
    %(prog)s --verify
    %(prog)s --verify --folders /etc /usr/bin

  Custom database file:
    %(prog)s --create --db custom_db.json
    %(prog)s --verify --db custom_db.json

  Exclude patterns:
    %(prog)s --create --exclude .log .tmp .cache
        """
    )

    # Help notes (checked before the mutually exclusive group so -H works standalone)
    parser.add_argument(
        "--help-notes", "-H",
        nargs="?",
        const="__all__",
        metavar="TOPIC",
        help=(
            "Show annotated help notes. Use -H alone for all topics, "
            f"or -H <topic> for one. Topics: {', '.join(HELP_NOTES.keys())}"
        ),
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--create", "-c",
        action="store_true",
        help="Create checksum database"
    )
    mode_group.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify files against database"
    )

    # Optional arguments
    parser.add_argument(
        "--folders", "-f",
        nargs="+",
        default=FOLDERS_TO_MONITOR,
        help=f"Folders to monitor (default: {', '.join(FOLDERS_TO_MONITOR)})"
    )
    parser.add_argument(
        "--db",
        default=DATABASE_FILE,
        help=f"Database file path (default: {DATABASE_FILE})"
    )
    parser.add_argument(
        "--exclude", "-e",
        nargs="+",
        default=[],
        help="Patterns to exclude from scanning (e.g., .log .tmp)"
    )

    # Handle -H / --help-notes before the required-group check fires,
    # so the user can run:  script.py -H         (all notes, no other flags)
    #                       script.py -H folders  (single topic, no other flags)
    import argparse as _ap
    pre = _ap.ArgumentParser(add_help=False)
    pre.add_argument("--help-notes", "-H", nargs="?", const="__all__", metavar="TOPIC")
    pre_args, _ = pre.parse_known_args()
    if pre_args.help_notes is not None:
        topic = None if pre_args.help_notes == "__all__" else pre_args.help_notes
        show_help_notes(topic)
        sys.exit(0)

    args = parser.parse_args()

    # Display configuration
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}File Integrity Monitor - SHA-256{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
    print(f"Mode: {Colors.BOLD}{'CREATE' if args.create else 'VERIFY'}{Colors.RESET}")
    print(f"Database: {args.db}")
    print(f"Folders to monitor:")
    for folder in args.folders:
        print(f"  - {folder}")
    if args.exclude:
        print(f"Exclude patterns: {', '.join(args.exclude)}")
    print()

    # Execute appropriate mode
    if args.create:
        create_database(args.folders, args.db, args.exclude)
    else:
        success = verify_files(args.folders, args.db, args.exclude)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
