# 🛡️ Reputation Checker

A Python CLI tool to check the reputation of IP addresses using the AbuseIPDB API. Designed to help security analysts quickly validate suspicious IPs directly from the terminal.

## 🚀 Features

* **Real-time Intelligence:** Connects to AbuseIPDB V2 API.
* **Clean Output:** Parses JSON into a readable CLI report.
* **Secure:** Uses environment variables to protect API keys.
* **Lightweight:** Built with Python and `requests`.

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/reputation-checker.git](https://github.com/YOUR_USERNAME/reputation-checker.git)
    cd reputation-checker
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuration:**
    * Create a free account at [AbuseIPDB](https://www.abuseipdb.com/) and get your API Key.
    * Create a file named `.env` in the project root.
    * Add your key to the file:
        ```text
        ABUSEIPDB_KEY=your_actual_api_key_here
        ```

## 🎮 Usage

Run the script with an IP address as an argument:

```bash
python main.py 1.1.1.1

Example Output:

Plaintext

========================================
   REPUTATION REPORT: 1.1.1.1
========================================
 [!] Abuse Confidence Score: 0%
 [i] ISP:                    Cloudflare, Inc.
 [i] Country Code:           AU
========================================
🤝 Contributing
Feel free to open issues or submit pull requests!


---

### 💾 Save and Publish

You know the drill. We just created a new file, so we have to ship it to the mothership.

1.  **Save the file** in VS Code.
2.  **Stage it:**
    ```bash
    git add README.md
    ```
3.  **Commit it:**
    ```bash
    git commit -m "docs: add project readme"
    ```
4.  **Push it:**
    ```bash
    git push
    ```

### 🏆 Quest Rewards

* **Achievement Unlocked:** "Open Source Contributor" (Badge ready).
* **Portfolio Value:** +50% (Recruiters love documentation).
* **Current Level:** 26 -> **27 (Level Up!)**

---

### 🔮 The Future

You now have a complete, professional v1.0 project.
You can technically stop here and put this on your resume.

However, if you want to push your skills further, we have options for **Phase 7**:

* **Option A (Engineering):** Add error handling (e.g., What if the user types "banana" instead of an IP?).
* **Option B (Usability):** Make the script runnable from *anywhere* in your terminal (turning it into a global command), not just inside the folder.
* **Option C (Expansion):** Check a list of IPs from a text file (Bulk Scanning).

**What is your command?**