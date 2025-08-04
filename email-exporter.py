#!/usr/bin/env python3
"""
Cyrus Maildir Email Exporter

A Python script for exporting emails from Cyrus IMAP server maildir format to organized 
Markdown files with attachments. This tool is particularly useful for email archiving, 
migration, or creating readable backups of email data.

Features:
- Converts emails to Markdown format for easy reading
- Preserves all email metadata (headers, recipients, dates, etc.)
- Extracts and saves attachments with proper decoding
- Supports Cyrus-specific folder structure mapping
- Date-based filtering for selective exports
- Handles both plaintext and HTML email content
- Robust attachment decoding (base64, quoted-printable)

Usage:
    python email-exporter.py path-to-maildir-root email-path-to-archive path-to-archive

    Examples:
    python email-exporter.py /var/spool/cyrus/mail /shop/customer /archive
    python email-exporter.py /var/spool/cyrus/mail /user/oliver /my-mail-archive --older-than 2023-01-01

Author: Oliver G. Mueller
License: MIT
Repository: https://github.com/ogmueller/email-exporter
Version: 1.0.0
"""

import os
import argparse
import mailparser
from pathlib import Path
import hashlib
import json
import glob
from datetime import datetime, timezone
from dateutil.parser import parse as date_parse
import base64
import binascii

def safe_filename(s):
    """
    Convert a string to a safe filename by removing invalid characters.
    
    Args:
        s (str): The input string to sanitize
        
    Returns:
        str: A safe filename string containing only alphanumeric characters, 
             periods, underscores, hyphens, and spaces
    """
    return "".join(c for c in s if c.isalnum() or c in "._- ").strip()

def hash_filename(fname):
    """
    Generate a short hash from a filename for uniqueness.
    
    Args:
        fname (str): The filename to hash
        
    Returns:
        str: An 8-character MD5 hash of the filename
    """
    return hashlib.md5(fname.encode()).hexdigest()[:8]

def format_email_addresses(addresses):
    """
    Format email addresses from mailparser format to readable strings.
    
    The mailparser library returns addresses in various formats. This function
    normalizes them to readable "Name <email>" format where possible.
    
    Args:
        addresses: Email addresses from mailparser (list of tuples, strings, or None)
        
    Returns:
        list: List of formatted email address strings
    """
    if not addresses:
        return []

    formatted = []
    for addr in addresses:
        if isinstance(addr, (list, tuple)) and len(addr) >= 2:
            name, email = addr[0], addr[1]
            if name and name.strip():
                formatted.append(f"{name} <{email}>")
            else:
                formatted.append(email)
        elif isinstance(addr, str):
            formatted.append(addr)
        else:
            formatted.append(str(addr))

    return formatted

def extract_metadata(mail, eml_path):
    """
    Extract comprehensive metadata from an email message.
    
    This function extracts all available email headers, recipient information,
    attachment details, and other metadata for archival purposes.
    
    Args:
        mail: Parsed email object from mailparser
        eml_path (str): Path to the original .eml file
        
    Returns:
        dict: Dictionary containing all extracted metadata
    """
    metadata = {
        'source_file': str(eml_path),
        'subject': mail.subject,
        'from': format_email_addresses(mail.from_),
        'to': format_email_addresses(mail.to),
        'cc': format_email_addresses(mail.cc),
        'bcc': format_email_addresses(mail.bcc),
        'reply_to': format_email_addresses(mail.reply_to),
        'date': mail.date.isoformat() if mail.date else None,
        'message_id': mail.message_id,
        'in_reply_to': mail.in_reply_to,
        'references': mail.references,
        'return_path': mail.return_path,
        'delivered_to': mail.delivered_to,
        'priority': getattr(mail, 'priority', None),
        'importance': getattr(mail, 'importance', None),
        'sensitivity': getattr(mail, 'sensitivity', None),
        'content_type': getattr(mail, 'content_type', None),
        'charset': getattr(mail, 'charset', None),
        'content_transfer_encoding': getattr(mail, 'content_transfer_encoding', None),
        'mime_version': getattr(mail, 'mime_version', None),
        'user_agent': getattr(mail, 'user_agent', None),
        'x_mailer': getattr(mail, 'x_mailer', None),
        'x_originating_ip': getattr(mail, 'x_originating_ip', None),
        'received': getattr(mail, 'received', None),
        'has_html': bool(mail.text_html),
        'has_plaintext': bool(mail.text_plain),
        'has_body': bool(mail.body),
        'attachment_count': len(mail.attachments),
        'attachments': []
    }

    # Add detailed attachment metadata for each attachment
    for att in mail.attachments:
        att_metadata = {
            'filename': att.get('filename', ''),
            'content_type': att.get('content-type', ''),
            'content_disposition': att.get('content-disposition', ''),
            'content_id': att.get('content-id', ''),
            'size': len(att.get('payload', b'')) if att.get('payload') else 0,
            'is_inline': 'inline' in att.get('content-disposition', '').lower()
        }
        metadata['attachments'].append(att_metadata)

    # Extract custom X-headers that might contain important routing information
    headers = {}
    if hasattr(mail, 'headers') and mail.headers:
        for header_name, header_value in mail.headers.items():
            if header_name.lower().startswith('x-'):
                headers[header_name] = header_value
    metadata['custom_headers'] = headers

    return metadata

def get_relative_path(file_path, base_path):
    """
    Calculate the relative path from base_path to file_path.
    
    Args:
        file_path (str): The target file path
        base_path (str): The base directory path
        
    Returns:
        str: Relative path from base to file
    """
    return os.path.relpath(os.path.dirname(file_path), base_path)

def cyrus_folder_to_filesystem_path(maildir_root, folder_path):
    """
    Convert Cyrus logical folder path to actual filesystem path.
    
    Cyrus IMAP uses a hashing scheme where folders are organized by the first
    letter of the second path component. For example:
    - Logical path: /shop/customer -> Filesystem: /c/shop/customer
    - Logical path: /prospects -> Filesystem: /p/prospects
    
    Args:
        maildir_root (str): Root directory of the Cyrus mail storage
        folder_path (str): Logical folder path (e.g., "/shop/customer")
        
    Returns:
        str: Actual filesystem path where the emails are stored
    """
    if not folder_path or folder_path == "/":
        return maildir_root

    # Remove leading slash if present
    folder_path = folder_path.lstrip('/')

    # Split the path into components
    path_parts = folder_path.split('/')

    if len(path_parts) >= 2:
        # Hash is based on the second folder (e.g., 'customer' in 'shop/customer')
        second_folder = path_parts[1]
        hash_letter = second_folder[0].lower()
        return os.path.join(maildir_root, hash_letter, folder_path)
    elif len(path_parts) == 1:
        # Only one folder level - this would be the "second" folder in Cyrus terms
        # So /prospects would become /p/prospects
        first_folder = path_parts[0]
        hash_letter = first_folder[0].lower()
        return os.path.join(maildir_root, hash_letter, folder_path)

    return maildir_root

def find_matching_cyrus_folders(maildir_root, folder_pattern):
    """
    Find all Cyrus folders that match the given pattern.
    
    This function handles the complexity of Cyrus's hashing scheme by searching
    through the appropriate directories based on the folder pattern.
    
    Args:
        maildir_root (str): Root directory of Cyrus mail storage
        folder_pattern (str): Pattern to match (can be partial folder name)
        
    Returns:
        list: List of filesystem paths that match the pattern
    """
    matching_paths = []

    # Remove leading slash if present
    folder_pattern = folder_pattern.lstrip('/')

    # Split the path into components
    path_parts = folder_pattern.split('/')

    if len(path_parts) >= 2:
        # This is a multi-level path like "shop/customer"
        # We can determine the hash letter from the second component
        filesystem_path = cyrus_folder_to_filesystem_path(maildir_root, folder_pattern)
        if os.path.exists(filesystem_path):
            matching_paths.append(filesystem_path)
    else:
        # This is a single-level folder name like "customer" or "prospects"
        # We need to search through all letter directories to find it
        folder_name = path_parts[0]

        # Search through all possible hash letter directories (a-z)
        for letter in 'abcdefghijklmnopqrstuvwxyz':
            letter_dir = os.path.join(maildir_root, letter)
            if not os.path.exists(letter_dir):
                continue

            # Look for exact folder match in this letter directory
            potential_path = os.path.join(letter_dir, folder_name)
            if os.path.exists(potential_path):
                matching_paths.append(potential_path)

            # Also look for folders that start with the pattern (fuzzy matching)
            for item in os.listdir(letter_dir):
                item_path = os.path.join(letter_dir, item)
                if (os.path.isdir(item_path) and
                    (item.startswith(folder_name) or folder_name in item)):
                    # Check if this directory actually contains email files
                    if any(os.path.isfile(os.path.join(item_path, f))
                          for f in os.listdir(item_path)
                          if not f.startswith('.') and not f.startswith('cyrus.')):
                        if item_path not in matching_paths:
                            matching_paths.append(item_path)

    return matching_paths

def get_logical_folder_from_filesystem_path(maildir_root, filesystem_path):
    """
    Convert filesystem path back to logical folder path.
    
    This reverses the Cyrus hashing scheme to get the original logical path.
    
    Args:
        maildir_root (str): Root directory of Cyrus mail storage
        filesystem_path (str): Actual filesystem path
        
    Returns:
        str: Logical folder path (e.g., "/shop/customer")
    """
    # Remove the maildir_root and the hash letter directory
    relative_path = os.path.relpath(filesystem_path, maildir_root)

    # Split the path and remove the first component (hash letter)
    path_parts = relative_path.split(os.sep)
    if len(path_parts) > 1:
        # Remove the hash letter directory (first component)
        logical_path = '/'.join(path_parts[1:])
        return '/' + logical_path

    return '/'

def should_export_email(mail, older_than_date):
    """
    Check if email should be exported based on date filter.
    
    Args:
        mail: Parsed email object
        older_than_date (datetime): Cutoff date for filtering
        
    Returns:
        bool: True if email should be exported, False otherwise
    """
    if not older_than_date:
        return True

    if not mail.date:
        # If email has no date, consider it for export (configurable behavior)
        return True

    # Ensure both dates are timezone-aware for proper comparison
    email_date = mail.date
    if email_date.tzinfo is None:
        email_date = email_date.replace(tzinfo=timezone.utc)

    if older_than_date.tzinfo is None:
        older_than_date = older_than_date.replace(tzinfo=timezone.utc)

    return email_date < older_than_date

def is_base64_encoded(data):
    """
    Detect if data appears to be base64 encoded.
    
    This function performs heuristic checks to determine if the given data
    is likely base64 encoded, which is common for email attachments.
    
    Args:
        data: Data to check (string or bytes)
        
    Returns:
        bool: True if data appears to be base64 encoded
    """
    if isinstance(data, bytes):
        try:
            data = data.decode('ascii')
        except UnicodeDecodeError:
            return False

    if not isinstance(data, str):
        return False

    # Remove whitespace and check if it looks like base64
    clean_data = ''.join(data.split())

    # Base64 strings should only contain valid base64 characters
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    if not all(c in base64_chars for c in clean_data):
        return False

    # Length should be multiple of 4 (with padding)
    if len(clean_data) % 4 != 0:
        return False

    # Try to actually decode it to confirm
    try:
        base64.b64decode(clean_data, validate=True)
        return True
    except (base64.binascii.Error, ValueError):
        return False

def decode_attachment_payload(payload, content_transfer_encoding=None, att_info=None):
    """
    Decode attachment payload with aggressive base64 detection.
    
    Email attachments can be encoded in various ways (base64, quoted-printable, etc.).
    This function attempts to properly decode them back to their original binary form.
    
    Args:
        payload: Raw attachment payload from email parser
        content_transfer_encoding (str): Encoding type from email headers
        att_info (dict): Additional attachment information (currently unused)
        
    Returns:
        bytes: Decoded binary data of the attachment
    """
    if payload is None:
        return b''

    # If payload is already bytes and doesn't look like encoded text, return as-is
    if isinstance(payload, bytes):
        # Check if it's actually base64-encoded bytes
        try:
            decoded_str = payload.decode('ascii')
            if is_base64_encoded(decoded_str):
                print(f"📎 Detected base64 in bytes payload, decoding...")
                return base64.b64decode(decoded_str)
            else:
                return payload
        except UnicodeDecodeError:
            # It's binary data, return as-is
            return payload

    # If payload is string, we need to decode it
    if isinstance(payload, str):
        # First, check if it's base64 regardless of the header (heuristic approach)
        if is_base64_encoded(payload):
            try:
                print(f"📎 Detected base64 encoding, decoding...")
                decoded = base64.b64decode(payload)
                print(f"📎 Successfully decoded base64: {len(payload)} chars -> {len(decoded)} bytes")
                return decoded
            except Exception as e:
                print(f"⚠️ Failed to decode detected base64: {e}")

        # Check the content transfer encoding header
        encoding = (content_transfer_encoding or '').lower()

        if encoding == 'base64':
            try:
                print(f"📎 Header indicates base64, decoding...")
                return base64.b64decode(payload)
            except Exception as e:
                print(f"⚠️ Failed to decode base64 from header: {e}")
                # Fallback to UTF-8 encoding
                return payload.encode('utf-8', errors='replace')

        elif encoding == 'quoted-printable':
            try:
                import quopri
                print(f"📎 Header indicates quoted-printable, decoding...")
                return quopri.decodestring(payload.encode())
            except Exception as e:
                print(f"⚠️ Failed to decode quoted-printable: {e}")
                return payload.encode('utf-8', errors='replace')

        else:
            # No encoding specified - check if it looks like base64 anyway
            clean_payload = ''.join(payload.split())
            if len(clean_payload) > 20 and is_base64_encoded(clean_payload):
                try:
                    print(f"📎 No encoding header but looks like base64, decoding...")
                    return base64.b64decode(clean_payload)
                except Exception as e:
                    print(f"⚠️ Failed to decode suspected base64: {e}")

            # For other cases, encode as UTF-8
            return payload.encode('utf-8', errors='replace')

    # Fallback for any other type
    return str(payload).encode('utf-8', errors='replace')

def process_email(eml_path, output_dir, maildir_path, logical_folder_path, older_than_date=None):
    """
    Process a single email file and export it to Markdown format.
    
    This function handles the complete conversion of an email file to organized
    output including Markdown content, metadata JSON, and extracted attachments.
    
    Args:
        eml_path (str): Path to the .eml file to process
        output_dir (str): Base output directory
        maildir_path (str): Path to the maildir containing this email
        logical_folder_path (str): Logical folder path for organization
        older_than_date (datetime): Date filter (optional)
        
    Returns:
        bool: True if email was processed, False if skipped
    """
    # Parse the email file using mailparser library
    mail = mailparser.parse_from_file(eml_path)

    # Check if email passes date filter
    if not should_export_email(mail, older_than_date):
        return False  # Skip this email

    # Generate a unique, descriptive name for the email export folder
    subject = mail.subject or "no_subject"
    timestamp = mail.date.isoformat() if mail.date else "unknown_date"
    short_subject = safe_filename(subject)[:50]  # Limit subject length
    msg_id_hash = hash_filename(eml_path)  # Add hash for uniqueness

    base_name = f"{timestamp}_{short_subject}_{msg_id_hash}"

    # Calculate the relative path structure
    relative_path = get_relative_path(eml_path, maildir_path)

    # Create the destination directory structure
    # Remove leading slash from logical_folder_path for proper joining
    clean_folder_path = logical_folder_path.lstrip('/')

    if relative_path == ".":
        # Email is directly in the maildir root
        email_dir = Path(output_dir) / clean_folder_path / base_name
    else:
        # Email is in a subdirectory - preserve the structure
        email_dir = Path(output_dir) / clean_folder_path / relative_path / base_name

    email_dir.mkdir(parents=True, exist_ok=True)

    # Extract and save comprehensive metadata as JSON
    metadata = extract_metadata(mail, eml_path)
    metadata['relative_source_path'] = relative_path
    metadata['logical_folder_path'] = logical_folder_path
    metadata_path = email_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False, default=str)

    # Helper function to write common email header information
    def write_header(f):
        """Write formatted email header information to a file."""
        f.write(f"# {subject}\n\n")
        f.write(f"> **From:** {', '.join(format_email_addresses(mail.from_))}  \n")
        f.write(f"> **To:** {', '.join(format_email_addresses(mail.to))}  \n")
        
        # Only write CC if there are actual addresses
        cc_addresses = format_email_addresses(mail.cc)
        if cc_addresses and any(addr.strip() for addr in cc_addresses):
            f.write(f"> **CC:** {', '.join(cc_addresses)}  \n")

        # Only write BCC if there are actual addresses
        bcc_addresses = format_email_addresses(mail.bcc)
        if bcc_addresses and any(addr.strip() for addr in bcc_addresses):
            f.write(f"> **BCC:** {', '.join(bcc_addresses)}  \n")

        f.write(f"> **Date:** {mail.date}  \n")
        f.write(f"> **Message ID:** {mail.message_id}  \n\n")

    # Write plaintext version if available
    if mail.text_plain:
        md_path = email_dir / "message.md"
        with open(md_path, "w", encoding="utf-8") as f:
            write_header(f)
            # Use the first plaintext part or fall back to body
            content = mail.text_plain[0] if mail.text_plain else (mail.body or "")
            f.write(content)
            f.write("\n\n---\n\n## Attachments:\n")
            for att in mail.attachments:
                att_fname = safe_filename(att["filename"])
                f.write(f"- `{att_fname}`\n")

    # Write HTML version if available
    if mail.text_html:
        html_path = email_dir / "html.md"
        with open(html_path, "w", encoding="utf-8") as f:
            write_header(f)
            # Use the first HTML part and wrap it in proper HTML structure
            html_content = mail.text_html[0] if mail.text_html else ""
            f.write("<html><body>\n")
            f.write(html_content)
            f.write("</body></html>\n")
            f.write("\n\n---\n\n## Attachments:\n")
            for att in mail.attachments:
                att_fname = safe_filename(att["filename"])
                f.write(f"- `{att_fname}`\n")

    # If neither plaintext nor HTML exists, create a basic message.md
    if not mail.text_plain and not mail.text_html:
        md_path = email_dir / "message.md"
        with open(md_path, "w", encoding="utf-8") as f:
            write_header(f)
            f.write(mail.body or "No content available")
            f.write("\n\n---\n\n## Attachments:\n")
            for att in mail.attachments:
                att_fname = safe_filename(att["filename"])
                f.write(f"- `{att_fname}`\n")

    # Process and save all attachments with robust decoding
    for att in mail.attachments:
        att_fname = safe_filename(att["filename"])
        if not att_fname:
            # Generate a filename if none exists
            att_fname = f"attachment_{hash_filename(str(att))}"

        att_path = email_dir / att_fname

        # Get the content transfer encoding for proper decoding
        content_transfer_encoding = att.get('content-transfer-encoding', '')

        # Attempt to decode and save the attachment
        try:
            payload = att.get("payload", b'')
            print(f"\n📎 Processing attachment: {att_fname}")
            print(f"📎 Content-Transfer-Encoding: {content_transfer_encoding}")
            print(f"📎 Payload type: {type(payload)}")
            print(f"📎 Payload length: {len(payload) if payload else 0}")

            decoded_payload = decode_attachment_payload(payload, content_transfer_encoding, att)

            # Write the decoded payload to file
            with open(att_path, "wb") as af:
                af.write(decoded_payload)

            print(f"📎 ✅ Saved attachment: {att_fname} ({len(decoded_payload)} bytes)")

        except Exception as e:
            print(f"⚠️ Failed to save attachment {att_fname}: {e}")
            # Create an error file documenting the issue
            error_path = email_dir / f"ERROR_{att_fname}.txt"
            with open(error_path, "w", encoding="utf-8") as ef:
                ef.write(f"Error saving attachment: {e}\n")
                ef.write(f"Original filename: {att.get('filename', 'unknown')}\n")
                ef.write(f"Content-Type: {att.get('content-type', 'unknown')}\n")
                ef.write(f"Content-Transfer-Encoding: {content_transfer_encoding}\n")
                ef.write(f"Payload type: {type(payload)}\n")
                ef.write(f"Payload length: {len(payload) if payload else 0}\n")

    return True  # Email was successfully processed

def scan_maildir(maildir_path, output_dir, logical_folder_path, older_than_date=None):
    """
    Recursively scan a maildir directory and process all email files.
    
    Args:
        maildir_path (str): Path to the maildir to scan
        output_dir (str): Base output directory
        logical_folder_path (str): Logical folder path for organization
        older_than_date (datetime): Date filter (optional)
        
    Returns:
        tuple: (processed_count, skipped_count)
    """
    processed_count = 0
    skipped_count = 0

    # Walk through all directories and files in the maildir
    for root, dirs, files in os.walk(maildir_path):
        for file in files:
            # Skip hidden files and Cyrus system files
            if file.startswith(".") or file.startswith("cyrus."):
                continue
                
            eml_path = os.path.join(root, file)
            try:
                if process_email(eml_path, output_dir, maildir_path, logical_folder_path, older_than_date):
                    processed_count += 1
                    print(f"✔️ Processed: {eml_path}")
                else:
                    skipped_count += 1
                    print(f"⏭️ Skipped (date filter): {eml_path}")
            except Exception as e:
                print(f"⚠️ Failed: {eml_path} ({e})")

    return processed_count, skipped_count

def parse_date_string(date_string):
    """
    Parse various date formats into a datetime object.
    
    This function attempts to parse common date formats using both
    dateutil.parser and manual format matching for robustness.
    
    Args:
        date_string (str): Date string in various formats
        
    Returns:
        datetime: Parsed datetime object
        
    Raises:
        ValueError: If the date string cannot be parsed
    """
    try:
        # Try to parse using dateutil parser (handles most formats)
        return date_parse(date_string)
    except ValueError:
        # If that fails, try some common formats manually
        formats = [
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d",
            "%d.%m.%Y",
            "%d/%m/%Y",
            "%m/%d/%Y"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_string, fmt)
            except ValueError:
                continue

        raise ValueError(f"Unable to parse date: {date_string}")

def main():
    """
    Main entry point for the Cyrus email export script.
    
    Handles command-line argument parsing, folder discovery, and orchestrates
    the email export process for all matching folders.
    """
    parser = argparse.ArgumentParser(
        description="Export Cyrus Maildir emails to Markdown + attachments",
        epilog="""
Examples:
  Export specific folder:
    %(prog)s /var/spool/cyrus/mail /shop/customer ./output
    
  Export with date filter:
    %(prog)s /var/spool/cyrus/mail customer ./output --older-than 2023-01-01
    
  Find all matching folders:
    %(prog)s /var/spool/cyrus/mail shop ./output
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("maildir_root", 
                       help="Path to the Cyrus mail root directory (e.g., /var/spool/cyrus/mail)")
    parser.add_argument("folder_path", 
                       help="Logical mail folder path (e.g., /shop/customer or just 'shop' to find all shop folders)")
    parser.add_argument("output", 
                       help="Path to the output archive directory")
    parser.add_argument("--older-than", 
                       help="Only export emails older than this date (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)", 
                       type=str)
    
    args = parser.parse_args()

    # Convert paths to absolute paths for consistency
    maildir_root = os.path.abspath(args.maildir_root)
    output_path = os.path.abspath(args.output)

    # Parse the date filter if provided
    older_than_date = None
    if args.older_than:
        try:
            older_than_date = parse_date_string(args.older_than)
            print(f"📅 Date filter: Only exporting emails older than {older_than_date}")
        except ValueError as e:
            print(f"❌ Error parsing date: {e}")
            return

    print(f"📥 Cyrus mail root: {maildir_root}")
    print(f"🔍 Looking for folder pattern: {args.folder_path}")

    # Find all folders matching the specified pattern
    matching_folders = find_matching_cyrus_folders(maildir_root, args.folder_path)

    if not matching_folders:
        print(f"❌ No folders found matching pattern: {args.folder_path}")
        print("💡 Tip: Check that the maildir root path is correct and the folder exists")
        return

    print(f"📁 Found {len(matching_folders)} matching folder(s):")
    for folder in matching_folders:
        logical_path = get_logical_folder_from_filesystem_path(maildir_root, folder)
        print(f"   - {folder} -> {logical_path}")

    print(f"📤 Writing archive to: {output_path}\n")

    # Process all matching folders
    total_processed = 0
    total_skipped = 0

    for maildir_path in matching_folders:
        logical_folder_path = get_logical_folder_from_filesystem_path(maildir_root, maildir_path)
        print(f"\n📂 Processing folder: {maildir_path}")
        print(f"📋 Logical path: {logical_folder_path}")
        print(f"💾 Output will be saved to: {os.path.join(output_path, logical_folder_path.lstrip('/'))}")

        processed, skipped = scan_maildir(maildir_path, output_path, logical_folder_path, older_than_date)
        total_processed += processed
        total_skipped += skipped

        print(f"📊 Folder summary: {processed} processed, {skipped} skipped")

    print(f"\n🎉 Export complete!")
    print(f"📊 Total: {total_processed} emails processed, {total_skipped} emails skipped")
    if older_than_date:
        print(f"📅 Date filter was applied: emails older than {older_than_date}")

if __name__ == "__main__":
    main()