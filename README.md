# Malicious Email Scorer

The Malicious Email Scorer is an intelligent email security tool designed to analyze incoming emails and provide a clear, explainable verdict (SAFE, SUSPICIOUS, or MALICIOUS) directly within your Gmail inbox.

## 1. Architecture

The system follows an Enterprise Clean Architecture pattern, decoupling the frontend user interface from the backend processing logic to ensure scalability and testability.

* **Frontend:** A Google Workspace Add-on built with Google Apps Script (`CardService`). It natively integrates into the Gmail UI, providing a seamless user experience across Desktop, iOS, and Android.
* **Backend:** A highly scalable REST API built with **FastAPI** (Python 3.13) and managed via **Poetry**.
* **Data Layer:** SQLite database using **SQLModel** (ORM). The Repository Pattern (`crud/`) strictly separates database queries from business logic. **Alembic** is used for database migrations.
* **Validation:** **Pydantic** schemas (`schemas/`) ensure strict validation of all incoming and outgoing API requests.

## 2. APIs Used

The backend orchestrates multiple asynchronous outbound requests to external threat intelligence providers to gather context about the email:

* **VirusTotal API v3:** Used to query URLs extracted from the email body to determine if they have been flagged by antivirus vendors as malicious or suspicious.
* **Google Safe Browsing API v4:** Used to check URLs against Google's constantly updated lists of unsafe web resources (e.g., social engineering, malware).
* **Gmail API:** Utilized strictly by the Google Apps Script frontend to extract the open email's sender, subject, body text, and `Authentication-Results` headers (SPF, DKIM, DMARC).

## 3. Implemented Features

* **Contextual Extraction:** Automatically extracts email headers, sender domains, and embedded URLs from the currently viewed email without requiring user input.
* **Heuristic Scoring Engine:** A transparent, deterministic scoring algorithm (unbounded) that evaluates threat intel data, domain spoofing metrics (SPF/DKIM failures), and content-based keywords.
* **Explainable Verdicts:** Provides human-readable reasons (e.g., "URL flagged by VirusTotal", "SPF Check Failed") alongside the final verdict so users understand *why* an email was flagged.
* **Personal Blocklist:** Users can proactively block specific email addresses or entire domains. Blocked senders bypass heuristics and are immediately flagged as MALICIOUS.
* **Scan History Audit Log:** Every processed email is recorded in the database, allowing for incident response tracking and future machine learning dataset generation.

## 4. Quick Start / Local Setup

Follow these steps to run the backend API locally.

### Prerequisites
* Python 3.13+ installed.
* [Poetry](https://python-poetry.org/docs/) installed for dependency management.

### Backend Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/matan60003/Malicious-Email-Scorer.git
   cd "Malicious Email Scorer"
   ```

2. **Install dependencies:**
   ```bash
   cd backend
   poetry install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the `backend/` directory (or export them):
   ```ini
   VIRUSTOTAL_API_KEY="your_vt_key_here"
   SAFE_BROWSING_API_KEY="your_sb_key_here"
   API_KEY_SECRET="super_secret_dev_key"
   ```

4. **Start the FastAPI Server:**
   *(Note: The SQLite database and tables will be automatically created on startup.)*
   ```bash
   poetry run uvicorn main:app --reload
   ```
   The API will be available at `http://localhost:8000`. You can view the interactive API documentation at `http://localhost:8000/docs`.

### Gmail Add-on Setup (Frontend)

To run the frontend UI directly inside your Gmail inbox, you must deploy the Google Apps Script code locally to your Google account.

1. **Create an Apps Script Project:**
   * Go to [script.google.com](https://script.google.com/) and click **New project**.
   * Name the project `Malicious Email Scorer`.
2. **Copy the Source Code:**
   * Open the `frontend/Code.js` file from this repository and copy its contents into the `Code.gs` file in the Apps Script editor.
3. **Configure the Manifest:**
   * In the Apps Script editor, click on **Project Settings** (the gear icon) and check **"Show 'appsscript.json' manifest file in editor"**.
   * Navigate back to the editor, open `appsscript.json`, and paste the contents of the `frontend/appsscript.json` file from this repository over it.
4. **Link the Backend URL & API Key:**
   * If you are running the backend locally on `localhost:8000`, you will need to expose it to the internet using a tool like [ngrok](https://ngrok.com/) (`ngrok http 8000`).
   * Update the `API_URL` variable at the very top of `Code.gs` to point to your public ngrok URL (e.g., `https://<your-ngrok-id>.ngrok-free.app/api/v1/scan`).
   * Update the `BACKEND_API_KEY` variable at the top of `Code.gs` to match the `API_KEY_SECRET` you defined in your backend `.env` file.
5. **Test the Add-on:**
   * Click **Deploy** -> **Test deployments**.
   * Ensure the application type is **Google Workspace Add-on**, then click **Install**.
   * Go to your Gmail inbox, open any email, and click the new Malicious Email Scorer icon in the right-hand side panel to view the verdict!

## 5. Known Limitations

* **Heuristic Reliance:** The scoring engine currently relies on static heuristic weights. Sophisticated zero-day phishing attacks that do not trigger VirusTotal, Safe Browsing, or keyword rules may evade detection.
* **No Attachment Scanning:** The project currently extracts and scans URLs and body text, but does not download, hash, or sandbox file attachments.
* **Single-Tenant Database:** The project utilizes a local SQLite database, which is excellent for a single-user deployment but lacks the concurrent write capabilities required for a massive multi-tenant SaaS deployment.
* **Server Hangs (No Timeout in Apps Script):** Google Apps Script's `UrlFetchApp.fetch()` does not support a custom timeout parameter. If the FastAPI backend hangs completely (rather than just experiencing API latency), the execution will block until it hits the hard 30-second Workspace Add-on limit. At that point, Google will forcibly terminate the execution and display an ungraceful error ("Card time out" or "Execution failed") to the user. This can be mitigated in production by running the backend behind a reverse proxy (which would return a 504 Gateway Timeout that the frontend can gracefully catch) or configuring strict worker timeouts (e.g., via Gunicorn).
