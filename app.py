from flask import Flask, render_template, render_template_string, request
import requests
import json
import os
import glob

app = Flask(__name__)

def fetch_cve_data():
    url = "https://cvefeed.io/api/user/products/cve-feed"
    headers = {'Authorization': 'Token 3657650656526e135b439aa5e3800de5f0c0fa5d'}
    try:
        response = requests.get(url, headers=headers)
        print(f"HTTP Status Code: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        print(f"Error fetching CVE data: {e}")
        return {}

def filter_high_critical_cves(cve_data):
    high_critical_cves = []
    for cve in cve_data.get('results', []):
        severity = cve.get('severity', '').upper()
        if severity in ['HIGH', 'CRITICAL']:
            cve_id = cve.get('id', "Unknown ID")
            cve_title = cve.get('title', "Unknown title")
            cvss_score = cve.get('cvss_score', "N/A")
            cisa_exploit = cve.get('cisa_exploit_added', "N/A")
            high_critical_cves.append({
                "id": cve_id,
                "title": cve_title,
                "cvss_score": cvss_score,
                "severity": severity,
                "cisa": cisa_exploit
            })
    return high_critical_cves

def update_cve_ids_file(cve_list):
    print("Attempting to update high_critical_cve_ids.json...")
    file_path = 'high_critical_cve_ids.json'
    existing_data = []

    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
            print(f"Existing data loaded. Entries: {len(existing_data)}")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON file: {e}. Using an empty list instead.")
    else:
        print(f"File {file_path} not found. Creating a new one.")

    existing_ids = {cve['id'] for cve in existing_data if 'id' in cve}
    print(f"Existing CVE IDs: {existing_ids}")

    new_cves = [cve for cve in cve_list if cve['id'] not in existing_ids]
    print(f"New CVEs to add: {len(new_cves)}")

    if new_cves:
        updated_data = new_cves + existing_data
        with open(file_path, 'w') as file:
            json.dump(updated_data, file, indent=4)
        print(f"Added {len(new_cves)} new CVE(s). Total CVEs now: {len(updated_data)}")
    else:
        print("No new CVEs to add. File remains unchanged.")



def find_cve_file(cve_id, root_dir):
    pattern = os.path.join(root_dir, '**', f'{cve_id}.json')
    matches = glob.glob(pattern, recursive=True)
    return matches[0] if matches else None

def read_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def format_cve_data(data, title, cvss_score, severity, cisa):
    """Format CVE data into a structured HTML card."""
    try:
       
        cve_info = data['cveMetadata']
        containers = data['containers']['cna']
        affected = containers.get('affected', [{}])[0]
        descriptions = containers.get('descriptions', [{}])[0].get('value', "Description not available")
        impacts = containers.get('impacts', [{}])[0].get('descriptions', [{}])[0].get('value', "Impact not available")
        problem_types = containers.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('description', "Not available")
        references_url = containers.get('references', [{}])[0].get('url', "No reference available")
        discovery_method = data.get('source', {}).get('discovery', "Unknown discovery method")
        generator = data.get('x_generator', {}).get('engine', "Generator unknown")

        

        cvss_class = "cvss-high" if severity == "HIGH" else "cvss-critical" if severity == "CRITICAL" else "cvss-low"

        affected_products = f"{affected.get('vendor', 'Unknown')} {affected.get('product', 'Unknown')}"
        
        version_affect = ", ".join(v['version'] for v in affected['versions'])
        return f"""
            <div class="cve-card">
                <div class="cve-header">
                    <h1>{cve_info['cveId']}
                        <span class="cvss-badge {cvss_class}">{cvss_score}</span>
                    </h1>
                    <span class="status status-badge">{cve_info['state']}</span>
                </div>

                <div class="meta-item">
                    <span class="label">Titre du CVE:</span>
                    <div>{title}</div>
                </div>

                <div class="meta-item">
                    <span class="label">Organisation assignée:</span>
                    <div>{cve_info['assignerShortName']}</div>
                </div>

                <div class="meta-item">
                    <span class="label">Date de publication:</span>
                    <div>{cve_info['datePublished']}</div>
                </div>

                <div class="meta-item">
                    <span class="label">Dernière mise à jour:</span>
                    <div>{cve_info['dateUpdated']}</div>
                </div>

                <div class="description-section">
                    <h2>Description</h2>
                    <div>{descriptions}</div>
                </div>

                <div class="impact-section">
                    <h2>Impact</h2>
                    <div>{impacts}</div>
                </div>

                <div class="description-section">
                    <h2>Type de Problème</h2>
                    <div>{problem_types}</div>
                </div>

                <div class="description-section">
                    <h2>Produits affectés</h2>
                    <div>{affected_products}</div>
                </div>

                <div class="reference-section">
                    <h2>Références</h2>
                    <div><a href="{references_url}" target="_blank">{references_url}</a></div>
                </div>

                <div class="meta-item">
                    <span class="label">Versions affectées:</span>
                    <div>{version_affect}</div>
                </div>

                <div class="meta-item">
                    <span class="label">Généré par:</span>
                    <div>{generator}</div>
                </div>

                <div class="impact-section">
                    <span class="label">CISA Exploitation:</span>
                    <div>{cisa}</div>
                </div>
            </div>

        """
    except KeyError as e:
        print(f"Skipping CVE due to missing key: {e}")
        return ""


@app.route('/')
def display_cve_cards():
    print("Fetching data and displaying CVE cards...")
    
    # Step 1: Fetch fresh data from the API
    cve_data = fetch_cve_data()
    if not cve_data:
        return "<div>Error fetching CVE data from API. Please try again later.</div>"

    # Step 2: Filter HIGH and CRITICAL CVEs
    high_critical_cves = filter_high_critical_cves(cve_data)
    
    # Step 3: Update the JSON file with new CVEs
    update_cve_ids_file(high_critical_cves)

    # Step 4: Generate CVE cards from the updated JSON file
    file_path = 'high_critical_cve_ids.json'
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            high_critical_cves_file = json.load(file)
            print(f"Loaded {len(high_critical_cves_file)} CVEs from file.")
    else:
        print(f"File {file_path} not found. No CVEs to display.")
        high_critical_cves_file = []

    cve_cards = []

    for cve in high_critical_cves_file:
        cve_id = cve.get('id', "N/A")
        title = cve.get('title', "Titre non disponible")
        cvss_score = cve.get('cvss_score', "N/A")
        severity = cve.get('severity', "N/A")
        cisa = cve.get('cisa', "N/A")

        file_path_cve_id = find_cve_file(cve_id, os.getcwd())
        if file_path_cve_id:
            data = read_json(file_path_cve_id)
            card_html = format_cve_data(data, title, cvss_score, severity, cisa)
            if card_html:
                cve_cards.append(card_html)
        else:
            print(f"No additional data found for CVE ID: {cve_id}")

    if not cve_cards:
        print("No CVEs to display.")
        cve_cards.append("<div class='no-result'>Aucun CVE trouvé pour la recherche.</div>")

    print(f"Rendering {len(cve_cards)} CVE cards...")
    return render_template('cve_cards.html', cards_html=''.join(cve_cards))



if __name__ == '__main__':
    # cve_data = fetch_cve_data()
    # if cve_data:
    #     high_critical_cves = filter_high_critical_cves(cve_data)
    #     update_cve_ids_file(high_critical_cves)
    app.run(debug=True)