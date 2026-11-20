# SentinelAPI — AI-Powered API Security Gateway

SentinelAPI is a real-time API security gateway and reverse proxy built to protect RESTful APIs from web attacks like SQL Injection, Cross-Site Scripting (XSS), and zero-day anomalies.

Using a Dual-Engine Machine Learning approach (Random Forest + Isolation Forest) and Shannon Entropy, it inspects incoming requests and blocks malicious payloads with `HTTP 403 Forbidden` in under 5 milliseconds, before they can reach the backend database.

---

## Key Features

* **Real-Time Reverse Proxy:** Intercepts incoming HTTP requests on port 8000 using FastAPI.
* **Dual-Engine AI Core:** 
  * Supervised Random Forest for known attacks (SQLi, XSS, Path Traversal).
  * Unsupervised Isolation Forest for zero-day and abnormal payloads.
* **Shannon Entropy Analysis:** Detects obfuscated, Base64, and hex-encoded exploit strings.
* **Live SOC Dashboard:** Dark-themed web dashboard with live request counters, incident tables, and an in-browser attack simulator.
* **Database Logging:** Asynchronously saves all security incidents and client IPs into PostgreSQL.

---

## Technologies Used

* **Backend & Proxy:** FastAPI, Uvicorn (ASGI)
* **Machine Learning:** Scikit-Learn, NumPy, Joblib
* **Database:** PostgreSQL, SQLAlchemy ORM
* **Frontend:** HTML5, CSS3, JavaScript, WebSockets, Chart.js
* **Testing:** Wireshark, PowerShell, Python

---

## Model Performance & Results

Trained and evaluated on the benchmark **CSIC 2010 HTTP Dataset** (61,065 requests):

* **Accuracy:** 97.02%
* **Precision:** 98.06%
* **Recall:** 94.61%
* **F1-Score:** 0.9630
* **ROC-AUC:** 0.9951
* **Average Latency:** < 5 ms

---

## How to Run the Project

### 1. Clone the Repository
```bash
git clone https://github.com/anusha-hajari/sentinel-api-gateway.git
cd sentinel-api-gateway
```

### 2. Set Up Virtual Environment & Install Packages
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Start the Server
```bash
python -m uvicorn app.main:app --port 8000 --reload
```

* **Live Dashboard:** http://127.0.0.1:8000
* **API Documentation (Swagger):** http://127.0.0.1:8000/docs

---

## How to Test

### 1. Test an Attack (SQL Injection)
Run this command in PowerShell to see the gateway block the attack:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/products?search=' OR '1'='1 --" -Method Get
```
*Expected Output:* `{"status": "BLOCKED", "threat_type": "SQL Injection (SQLi)", "confidence": "99.0%"}`

### 2. Test Safe Traffic (Clean Request)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/products?search=laptop" -Method Get
```
*Expected Output:* `HTTP 200 OK` (Clean product data returned)

### 3. Automated Test Suite
To fire automated test requests:
```bash
python simulator/attack_sim.py
```

---

## Author

* **Anusha Hajari**
* B.Tech Computer Science & Engineering
* Medi-Caps University, Indore