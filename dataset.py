import re
import concurrent.futures
import requests
from bs4 import BeautifulSoup

# The directory string exactly as provided
DIRECTORY_TEXT = """
1. Autonomous Vulnerability Management & Code Remediation
VulRepair Repository (AWSM Research Lab): Located at github.com/awsm-research/VulRepair.
Security Vuln Patches (HuggingFace Hub): Found at rgaucher/security-vuln-patches.
Project Discovery Nuclei-Templates (GitHub): Available at github.com/projectdiscovery/nuclei-templates.
Big-Vul Dataset: git modifications.
NIST National Vulnerability Database (NVD) JSON Feeds: Available at nvd.nist.gov/vuln/data-feeds.

2. SOAR Orchestration & Playbook Engine
The Primus Dataset (Trend Micro Lab): Available on HuggingFace at trendmicro-ailab/primus-67b1fd27052b802b4af9d243.
RE&CT Framework Data (MITRE): Located at github.com/atc-project/rect.
AWS Incident Response Playbooks: Found at github.com/aws-samples/aws-incident-response-playbooks.
Evol-Instruct-Code (GenAI Labs): Available on HuggingFace at GenAI-Labs/Evol-Instruct-Code.
Foundation Sec 8B (Cisco Systems Lab): Found at Cisco/Foundation-Sec-8B on HuggingFace.
Cybersecurity SFT Dataset (Moro Hub): Available at moro72842/cybersecurity-sft-dataset.
AI Agent Tool Debugging Prompt Library: Found at Chemically-motivated/AI-Agent-Generating-Tool-Debugging-Prompt-Library on HuggingFace.

3. SIEM Ingestion & Parser Engine
EVTX Attack Samples (Sallam Bousseaden): Found at github.com/sbousseaden/EVTX-ATTACK-SAMPLES.
SecRepo Security Data Warehouse: Accessible at secrepo.com.
The Spider Text-to-SQL Dataset: Available on HuggingFace Hub.

4. Incident Response (IR) Ticketing & Case Management
Trendyol Cybersecurity Instruction Tuning Dataset: Available at Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset on HuggingFace.
CybersecurityQAA (Rowden): Hosted on HuggingFace at Rowden/CybersecurityQAA.
Kaggle Cybersecurity Incident Structural Dataset: Available at mustafahabeeb90/cybersecurity-incident-dataset.
NIST SP 800-61 Rev. 2 Training Texts: Publicly available via the NIST Computer Security Resource Center.

5. Next-Gen Antivirus (NGAV) & Behavioural EDR Core
DeceptionPro EDR Telemetry Sample: Hosted on HuggingFace at DeceptionPro/EDR_Telemetry_Sample.
BCCC MalMem SnapLog 2025 (York University): Snapshot logging database.
EMBER2024 (Elastic Malware Benchmark Dataset): Found at github.com/futurecomputing4ai/ember2024.
SOREL-20M (Sophos/ReversingLabs): Located at github.com/sophos-ai/SOREL-20M.
"""

def extract_and_normalize_links(text):
    """
    Parses the text line by line to extract domain URLs and user/repo slugs, 
    normalizing them into functional absolute target URLs.
    """
    urls = set()
    lines = text.split('\n')
    
    # Patterns for catching standard domains and user/repo styles
    domain_regex = re.compile(r'([a-zA-Z0-9.-]+\.(com|gov|org|net)(/[^\s,)]*)?)')
    slug_regex = re.compile(r'([a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_.]+(?:-[a-zA-Z0-9\-_.]+)*)')

    for line in lines:
        if not line.strip():
            continue
        
        # Scenario A: Explicit domain names present (e.g., github.com, secrepo.com)
        domain_match = domain_regex.search(line)
        if domain_match:
            url = domain_match.group(1)
            if not url.startswith('http'):
                url = 'https://' + url
            urls.add(url.rstrip('.'))
            continue
            
        # Scenario B: Naked Hugging Face repository slugs (e.g., username/repo-name)
        if "HuggingFace" in line or "Hugging Face" in line:
            slug_match = slug_regex.search(line)
            if slug_match:
                slug = slug_match.group(1)
                # Catch collections vs standard dataset repos
                if "primus" in slug:
                    url = f"https://huggingface.co/collections/{slug}"
                else:
                    url = f"https://huggingface.co/datasets/{slug}"
                urls.add(url)
                
    return sorted(list(urls))

def trawl_url(url):
    """
    Hits the target endpoint, collects HTTP health metrics, 
    and extracts metadata titles to verify validity.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cybersecurity-Data-Trawler/1.0'
    }
    try:
        # Using a 10 second timeout to handle slow remote git servers cleanly
        response = requests.get(url, headers=headers, timeout=10)
        status_code = response.status_code
        
        if status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else "No Title Found"
            # Truncate clean titles to keep console reporting readable
            title = (title[:50] + '...') if len(title) > 50 else title
            return {"url": url, "status": "ONLINE", "code": status_code, "title": title}
        else:
            return {"url": url, "status": "ACCESSIBLE_BUT_ERR", "code": status_code, "title": "N/A"}
            
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "OFFLINE_OR_TIMEOUT", "code": 0, "title": str(e.__class__.__name__)}

def run_trawler():
    print("[*] Parsing directory strings and generating target scopes...")
    targets = extract_and_normalize_links(DIRECTORY_TEXT)
    
    print(f"[*] Found {len(targets)} normalized endpoints. Initiating parallel crawler matrix...")
    print("-" * 90)
    print(f"{'TARGET URL':<50} | {'STATUS':<15} | {'HTTP/ERR'}")
    print("-" * 90)
    
    # Use ThreadPoolExecutor to run tasks concurrently without serial I/O bottlenecks
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(trawl_url, targets)
        
        for record in results:
            print(f"{record['url'][:48]:<50} | {record['status']:<15} | {record['code'] if record['code'] != 0 else record['title']}")

if __name__ == "__main__":
    run_trawler()