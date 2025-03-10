import json
from collections import Counter

def count_results(json_file):
    # Load and parse the JSON data
    data = json.loads(json_file)
    
    # Get the results array
    results = data.get("results", [])
    
    # Create separate counters for each severity level
    severity_counters = {
        'critical': Counter(),
        'high': Counter(),
        'medium': Counter(),
        'low': Counter(),
        'unknown': Counter()
    }
    
    # Extract ruleIds and categorize by severity
    for result in results:
        rule_id = result.get("ruleId")
        # Get severity from the result, defaulting to 'unknown'
        severity = result.get("severity", "unknown").lower()
        
        if rule_id:
            if severity not in severity_counters:
                severity = "unknown"
            severity_counters[severity][rule_id] += 1
    
    return severity_counters

# Example usage
with open('/Users/samuelberston/Documents/MICS/courses/capstone/demo/scanner/data/juice-shop-codeql.json', 'r') as file:
    json_content = file.read()
    rule_frequencies = count_results(json_content)
    
    # Print total number of results for each severity
    total_results = sum(sum(counter.values()) for counter in rule_frequencies.values())
    print(f"Total number of results: {total_results}")
    
    # Print each rule and its frequency grouped by severity
    print("\nRule frequencies by severity:")
    for severity, counter in rule_frequencies.items():
        if counter:  # Only print severity levels that have results
            print(f"\n{severity.upper()}:")
            for rule, count in counter.most_common():
                print(f"{rule}: {count}")