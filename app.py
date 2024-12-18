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
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching CVE data: {e}")
        return {}

def filter_high_critical_cves(cve_data):
    """
    Filtre les CVE de gravité HIGH ou CRITICAL et retourne un dictionnaire {id: score}.
    """
    high_critical_cves = []
    for cve in cve_data.get('results', []):
        if cve.get('severity', '').upper() in ['HIGH', 'CRITICAL']:
            cve_id = cve.get('id', "Unknown ID")
            cve_title = cve.get('title', "Unknow title")
            cvss_score = cve.get('cvss_score', "N/A")
            severity = cve.get('severity', "N/A")
            cisa_exploit = cve.get('cisa_exploit_added', "N/A")

            high_critical_cves.append({"id": cve_id, "title":cve_title, "cvss_score": cvss_score, "severity":severity,"cisa":cisa_exploit})
    return high_critical_cves


def update_cve_ids_file(cve_list):
    """
    Met à jour le fichier JSON avec les nouveaux CVE et leurs scores CVSS.
    Les nouvelles entrées sont ajoutées en haut du fichier.
    """
    file_path = 'high_critical_cve_ids.json'
    existing_data = []

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                print("Error decoding JSON. Using an empty list.")

    if not all(isinstance(item, dict) for item in existing_data):
        existing_data = []

    existing_ids = {cve['id'] for cve in existing_data}
    new_cves = [cve for cve in cve_list if cve['id'] not in existing_ids]

    if new_cves:
        updated_data = new_cves + existing_data
        with open(file_path, 'w') as file:
            json.dump(updated_data, file, indent=4)
        print(f"Added {len(new_cves)} new CVE(s) at the top of the file.")
    else:
        print("No new CVEs to add.")



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
    query = request.args.get('q', "").strip().lower()

    file_path = 'high_critical_cve_ids.json'
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            high_critical_cves_file = json.load(file)
    else:
        high_critical_cves_file = []

    cve_cards = []

    for cve in high_critical_cves_file:
        cve_id = cve.get('id', "N/A")
        title = cve.get('title', "Titre non disponible")
        cvss_score = cve.get('cvss_score', "N/A")
        severity = cve.get('severity', "N/A")
        cisa = cve.get('cisa', "N/A")

        if query and query not in cve_id.lower() and query not in title.lower():
            continue

        file_path_cve_id = find_cve_file(cve_id, os.getcwd())
        if file_path_cve_id:
            data = read_json(file_path_cve_id)
            card_html = format_cve_data(data, title, cvss_score, severity, cisa)
            if card_html:
                cve_cards.append(card_html)

    if not cve_cards and query:
        cve_cards.append("<div class='no-result'>Aucun CVE trouvé pour la recherche.</div>")

    return render_template('cve_cards.html', cards_html=''.join(cve_cards))


if __name__ == '__main__':
    app.run(debug=True)