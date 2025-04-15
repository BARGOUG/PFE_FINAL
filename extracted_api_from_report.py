import json

def extract_apis_from_report(report_path):
    with open(report_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    apis = set()

    # From behavior section
    behavior = data.get('behavior', {})
    processes = behavior.get('processes', [])
    for process in processes:
        calls = process.get('calls', [])
        for call in calls:
            api = call.get('api')
            if api:
                apis.add(api)

    # From info section (just in case)
    info = data.get('info', {})
    if 'resolved_apis' in info:
        resolved_apis = info['resolved_apis']
        for api in resolved_apis:
            apis.add(api)

    # Return sorted APIs as a single string separated by spaces
    return ' '.join(sorted(apis))

# Example usage:
report_path = '/opt/CAPEv2/storage/analyses/latest/reports/report.json'
output_path = 'report_results/report.txt'

# Extract API calls
api_list = extract_apis_from_report(report_path)

# Save the API calls to a text file
with open(output_path, 'w', encoding='utf-8') as output_file:
    output_file.write(api_list)

print(f"API calls have been saved to {output_path}")
