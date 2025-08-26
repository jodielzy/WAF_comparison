# WAF Comparison Project

This repository contains my internship project @ Akamai, focused on **creating a tool to baseline the effectiveness of different Web Application Firewalls (WAFs)**.  

The goal is to provide a **repeatable methodology and infrastructure** to evaluate how well WAF solutions:  
- Detect and mitigate malicious traffic (true positives).  
- Avoid blocking legitimate traffic (false positives).  
- Balance **security coverage vs. precision**.  

The WAFs tested in this project include:  
- [**Akamai CDN & App & API Protector (AAP)**](https://www.akamai.com/)  
- [**BunkerWeb**](https://bunkerweb.io/)  
- [**Open AppSec**](https://www.openappsec.io/) (used as the pen-testing and benchmarking tool)  

---

## Project Overview

This project uses **Terraform** to automate:  
1. Provisioning a [**DVWA (Damn Vulnerable Web Application)**](https://github.com/digininja/DVWA) container on Linode.  
2. Setting up each WAF (Akamai AAP, BunkerWeb) to **proxy traffic** to DVWA.  
3. Running automated tests (via Open AppSec’s runner) to measure WAF effectiveness.  

The project is split into three subdirectories:  
- `akamai_cdn_aap/` – Setup for Akamai CDN + AAP  
- `bunkerweb/` – Setup for BunkerWeb  
- `openappsec/` – Baseline testing using Open AppSec  

---

## Prerequisites

Before you begin, ensure you have:

1. **Terraform installed**  
   👉 [Terraform installation guide](https://www.linode.com/docs/guides/how-to-build-your-infrastructure-using-terraform-and-linode/)

2. **Akamai API credentials and account details**  
   👉 [Akamai Terraform Provider Docs](https://techdocs.akamai.com/terraform/docs/overview)

3. **Access to Akamai Control Center** and an **existing CP Code** for CDN/AAP setup.

4. **Python and Python virtual environment installed**

5. **Clone this repository**
With Git installed, run:

```bash
git clone https://github.com/jodielzy/WAF_comparison.git
```

---

## 1. Setting up Akamai CDN and AAP

This section provisions **Akamai CDN + App & API Protector (AAP)** using Terraform.

### Steps

1. Change directory:
   ```bash
   cd akamai_cdn_aap
   ```

2. Fill in your credentials and account details in:
   ```
   terraform.tfvars
   ```

3. First, initialize the Terraform configuration:
   ```bash
   terraform init
   ```

4. Next, run Terraform to generate the certificate enrollment:
   ```bash
   terraform apply -target=akamai_cps_dv_enrollment.edge_enrollment -auto-approve
   ```

5. Then run a full apply to deploy everything:
   ```bash
   terraform apply -auto-approve
   ```
---

## 2. Setting up BunkerWeb

This section provisions **BunkerWeb WAF** in front of DVWA.

### Steps

1. Change directory:
   ```bash
   cd bunkerweb
   ```

2. Fill in your credentials and account details in:
   ```
   variables_template.tfvars
   ```

3. First, initialize the Terraform configuration:
   ```bash
   terraform init
   ```

4. Run Terraform:
   ```bash
   terraform apply -auto-approve
   ```

---

## Verifying Setup

After setting up the WAFs, you can test if everything is working by visiting the **server name/hostname** you provided.  
You should see the **DVWA main page**.

---

## 3. Setting up Open AppSec (Pen-testing)

This section runs the pen-testing and benchmarking framework, based on  
👉 [openappsec/waf-comparison-project](https://github.com/openappsec/waf-comparison-project).

### Steps

1. Change directory:
   ```bash
   cd openappsec
   ```

2. Update the target **URL** in `config.py`.
- By default, update this with the server name you have provided for Bunkerweb WAF set-up, and hostname you have provided for Akamai CDN + AAP set-up.
- You may also test any other URL by replacing it here

3. Create a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Run the benchmark:
   ```bash
   python3 runner.py
   ```

6. (Optional) Run with a smaller sample size:
   ```bash
   SMOKE_N=10 python3 runner.py
   ```

### Results
Test results are saved in the **`Output/`** folder after running `runner.py`.

The results provide a detailed breakdown of WAF effectiveness across multiple dimensions:

- **True Positive Rate (TPR):** Percentage of malicious requests correctly blocked.  
- **True Negative Rate (TNR):** Percentage of legitimate requests correctly allowed.  
- **False Positive Rate (FPR):** Percentage of legitimate requests incorrectly blocked.  
- **False Negative Rate (FNR):** Percentage of malicious requests incorrectly allowed.  
- **Balanced Accuracy:** Average of TPR and TNR, giving an overall fairness metric between catching attacks and avoiding false alarms.  
- **WAF_Block_Rate_Summary:** Summarizes how often each WAF blocked traffic across categories (e.g., SQLi, XSS, traversal), breakdown of the true positives.
- **Misclassifications_Report:** Lists cases where the WAF misclassified requests (false positives or false negatives).
---

## Security Precautions

Since DVWA is intentionally vulnerable, make sure to secure your setup:

1. **Initial Setup:**  
   - Visit the URL in your browser.  
   - Click **"Create/Reset Database"** to initialize it.  

2. **Login with Default Credentials:**  
   - Username: `admin`  
   - Password: `password`  

3. **Change Password Immediately:**  
   - Go to the **"CSRF" page** in DVWA.  
   - Change the default password to a stronger one.  

4. **Akamai internal testing:**  
   - Add Akamai firewall rules for your Linode instances to restrict external access.  

---

## Tearing Down

To destroy the infrastructure for each WAF setup, run in the respective directory:

```bash
terraform destroy
```

---

## Credits

- [**Open AppSec WAF Comparison Project**](https://github.com/openappsec/waf-comparison-project) – baseline testing framework  
- [**Damn Vulnerable Web Application (DVWA)**](https://github.com/digininja/DVWA) – target application for testing  
- [**Akamai**](https://www.akamai.com/) – CDN and AAP solution  
- [**BunkerWeb**](https://bunkerweb.io/) – open-source WAF  

---

## License

This project is for **educational and research purposes** during my internship at Akamai.  



