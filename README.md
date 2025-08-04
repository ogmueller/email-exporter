# email-exporter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

Export mailboxes (e.g. Cyrus IMAP) to organized Markdown files with decoded attachments and metadata. Perfect to archive your emails into a file structure for long time storage. Enables you to cleanup your mail server.

## 🌟 Features

- **📄 Markdown Conversion**: Converts emails to readable Markdown format with proper formatting
- **📎 Attachment Handling**: Extracts and saves all attachments with proper decoding (base64, quoted-printable)
- **🗂️ Organized Structure**: Creates logical folder structures preserving email organization
- **📋 Metadata Preservation**: Saves complete email headers and metadata as JSON
- **📅 Date Filtering**: Export only emails older than a specific date
- **🔍 Smart Folder Discovery**: Automatically finds matching folders in Cyrus IMAP structure
- **🏷️ HTML & Plaintext Support**: Handles both HTML and plaintext email content
- **🔒 Robust Error Handling**: Gracefully handles corrupted or malformed emails

## 📋 Requirements

- **Python 3.7+**
- **mailparser** library for email parsing
- **dateutil** library for date parsing
- **pathlib** (included in Python 3.4+)

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ogmueller/email-exporter.git
   cd email-exporter
   ```

2. **Install dependencies:**
   ```bash
   pip install mailparser python-dateutil
   ```

    or use your Linux distributions' packages if exist

   ```bash
   # example for debian based Linux
   apt install python3-dateutil
   ```

## 📖 Usage

### Basic Usage
```bash
python email-exporter.py <maildir_root> <folder_path> <output_directory>
```
### Command Line Arguments

- `maildir_root`: Path to the Cyrus mail root directory (e.g., `/var/spool/cyrus/mail`)
- `folder_path`: Logical mail folder path (e.g., `/shop/customer` or just `shop`)
- `output_directory`: Path where the exported files will be saved
- `--older-than`: *(Optional)* Only export emails older than specified date

### 💡 Examples

#### Export a specific customer folder:
```bash
python email-exporter.py /var/spool/cyrus/mail /shop/customer ./my-archive
```
#### Export all emails from a user's inbox:
```bash
python email-exporter.py /var/spool/cyrus/mail /user/john ./john-backup
```
#### Export emails older than a specific date:
```bash
python email-exporter.py /var/spool/cyrus/mail /user/jane ./jane-archive --older-than 2023-01-01
```
#### Find and export all folders matching a pattern:
```bash
python email-exporter.py /var/spool/cyrus/mail shop ./shop-archive
```
## 📁 Output Structure

The tool creates a well-organized directory structure for your exported emails:
```

output-directory/
├── shop/
│   └── customer/
│       ├── 2023-10-15T14:30:00_Important_Meeting_a1b2c3d4/
│       │   ├── message.md          # Plaintext email content
│       │   ├── html.md             # HTML email content (if available)
│       │   ├── metadata.json       # Complete email metadata
│       │   ├── attachment1.pdf     # Decoded attachment
│       │   └── attachment2.jpg     # Decoded attachment
│       └── 2023-10-16T09:15:00_Project_Update_e5f6g7h8/
│           ├── message.md
│           ├── metadata.json
│           └── report.xlsx
```
### File Types Explained

- **`message.md`**: Contains the email content in Markdown format with headers
- **`html.md`**: HTML version of the email (when available)
- **`metadata.json`**: Complete email metadata including headers, recipients, dates, attachment info
- **Attachment files**: All email attachments decoded and saved with original filenames

## 📊 Example Output

### Sample message.md:
```markdown
# Important Project Meeting

> **From:** John Doe <john@company.com>  
> **To:** Jane Smith <jane@company.com>  
> **Date:** 2023-10-15T14:30:00+00:00  
> **Message ID:** <abc123@company.com>  

Hi Jane,

I wanted to follow up on our project discussion. Please review the attached documents before our meeting tomorrow.

Best regards,
John

---

## Attachments:
- `project-proposal.pdf`
- `budget-overview.xlsx`
```
### Sample metadata.json:
```
json
{
  "source_file": "/var/spool/cyrus/mail/c/shop/customer/1234",
  "subject": "Important Project Meeting",
  "from": ["John Doe <john@company.com>"],
  "to": ["Jane Smith <jane@company.com>"],
  "cc": [],
  "date": "2023-10-15T14:30:00+00:00",
  "message_id": "<abc123@company.com>",
  "has_html": true,
  "has_plaintext": true,
  "attachment_count": 2,
  "attachments": [
    {
      "filename": "project-proposal.pdf",
      "content_type": "application/pdf",
      "size": 245760,
      "is_inline": false
    }
  ]
}
```
## 🔧 Advanced Usage

### Cyrus IMAP Folder Structure

The tool automatically handles Cyrus IMAP's hashing scheme where folders are organized by the first letter of the folder name:
- Logical path: `/shop/customer` → Filesystem: `/c/shop/customer/`
- Logical path: `/user/john` → Filesystem: `/j/user/john/`

### Date Filtering

Use various date formats with the `--older-than` option:
```
bash
# Different supported date formats
--older-than 2023-01-01
--older-than "2023-01-01 15:30:00"
--older-than 2023/01/01
--older-than 01.01.2023
```
### Pattern Matching

The folder search supports pattern matching:
- `shop` - Finds all folders containing "shop"
- `/specific/path` - Exact path matching
- `customer` - Finds all folders named "customer" across all hash directories

## 🐛 Troubleshooting

### Common Issues

1. **"No folders found"**: Check that the maildir root path is correct and accessible
2. **Permission errors**: Ensure you have read access to the Cyrus mail directories
3. **Attachment decoding errors**: The tool handles most encoding issues gracefully and creates error files for problematic attachments

### Debug Information

The tool provides detailed output during execution:
```

📥 Cyrus mail root: /var/spool/cyrus/mail
🔍 Looking for folder pattern: shop/customer
📁 Found 1 matching folder(s):
   - /var/spool/cyrus/mail/c/shop/customer -> /shop/customer
📤 Writing archive to: ./output

📂 Processing folder: /var/spool/cyrus/mail/c/shop/customer
✔️ Processed: /var/spool/cyrus/mail/c/shop/customer/1234
📎 Processing attachment: report.pdf
📎 ✅ Saved attachment: report.pdf (245760 bytes)

🎉 Export complete!
📊 Total: 15 emails processed, 3 emails skipped
```
## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Oliver G. Mueller**
- GitHub: [@ogmueller](https://github.com/ogmueller)
- Repository: [https://github.com/ogmueller/email-exporter](https://github.com/ogmueller/email-exporter)

## 🙏 Acknowledgments

- Built with [mailparser](https://pypi.org/project/mailparser/) for robust email parsing
- Uses [python-dateutil](https://pypi.org/project/python-dateutil/) for flexible date handling
```
