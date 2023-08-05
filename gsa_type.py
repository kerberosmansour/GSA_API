import pandas as pd
import requests
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create empty list for storing all the data
data = []

# Load JSON data from API
try:
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {os.getenv("GITHUB_APIs_TOKEN")}',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    params = {
        'type': 'malware',
        'per_page': 100
    }
    while True:
        response = requests.get('https://api.github.com/advisories', headers=headers, params=params)
        response.raise_for_status()
        page_data = json.loads(response.text)
        data.extend(page_data)
        if 'next' in response.links:
            next_url = response.links['next']['url']
            if 'after=' in next_url:
                params['after'] = next_url.split('after=')[1]
            else:
                break
        else:
            break
        print(f"Retrieved {len(data)} records so far...")
except requests.exceptions.RequestException as e:
    print(f'Error retrieving data from API: {e}')
    data = []

# Create empty lists for each column
ghsa_id = []
cve_id = []
url = []
summary = []
description = []
severity = []
source_code_location = []
published_at = []
ecosystem = []
name = []
first_patched_version = []
vulnerable_version_range = []

# Loop through each item in the JSON data and extract the relevant information
for item in data:
    for vulnerability in item.get('vulnerabilities', []):
        package = vulnerability.get('package', {})
        ghsa_id.append(item.get('ghsa_id', None))
        cve_id.append(item.get('cve_id', None))
        url.append(item.get('url', None))
        summary.append(item.get('summary', None))
        description.append(item.get('description', None))
        severity.append(item.get('severity', None))
        source_code_location.append(item.get('source_code_location', None))
        published_at.append(item.get('published_at', None))
        ecosystem.append(package.get('ecosystem', None))
        name.append(package.get('name', None))
        first_patched_version.append(vulnerability.get('first_patched_version', None))
        vulnerable_version_range.append(vulnerability.get('vulnerable_version_range', None))

# Create a DataFrame with the extracted information
df = pd.DataFrame({
    'ghsa_id': ghsa_id,
    'cve_id': cve_id,
    'url': url,
    'summary': summary,
    'description': description,
    'severity': severity,
    'source_code_location': source_code_location,
    'published_at': published_at,
    'ecosystem': ecosystem,
    'name': name,
    'first_patched_version': first_patched_version,
    'vulnerable_version_range': vulnerable_version_range
})

# Save the DataFrame to a parquet file
df.to_parquet('data.parquet')

# Print the DataFrame
print(df)
